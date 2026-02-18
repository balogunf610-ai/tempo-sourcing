;; Tempo-Sourcing: Ethical Supply Chain Management

;; This contract implements:
;;   - Supply chain stage registration and transitions
;;   - Multi-stakeholder validation (supplier, auditor, community, sensor)
;;   - Dynamic Compliance Contracts (DCC) with ESG scoring
;;   - Graduated penalty system based on compliance metrics
;;   - Supplier rating management

;; Constants
(define-constant CONTRACT-OWNER tx-sender)

(define-constant ERR-NOT-AUTHORIZED        (err u100))
(define-constant ERR-SUPPLIER-NOT-FOUND    (err u101))
(define-constant ERR-SHIPMENT-NOT-FOUND    (err u102))
(define-constant ERR-ALREADY-VALIDATED     (err u103))
(define-constant ERR-STAGE-NOT-READY       (err u104))
(define-constant ERR-INVALID-SCORE         (err u105))
(define-constant ERR-ALREADY-REGISTERED    (err u106))
(define-constant ERR-THRESHOLD-NOT-MET     (err u107))

;; Validator roles
(define-constant ROLE-SUPPLIER   u1)
(define-constant ROLE-AUDITOR    u2)
(define-constant ROLE-COMMUNITY  u3)
(define-constant ROLE-SENSOR     u4)

;; Shipment stages
(define-constant STAGE-CREATED    u0)
(define-constant STAGE-SOURCING   u1)
(define-constant STAGE-PRODUCTION u2)
(define-constant STAGE-LOGISTICS  u3)
(define-constant STAGE-DELIVERED  u4)

;; Minimum ESG score (out of 100) required to advance a stage
(define-constant MIN-ESG-SCORE u60)

;; ============================================================
;; Data Maps and Variables
;; ============================================================

;; Registry of approved validators and their roles
(define-map validators
  { validator: principal }
  { role: uint, active: bool }
)

;; Supplier profiles with cumulative compliance rating
(define-map suppliers
  { supplier: principal }
  {
    name: (string-ascii 64),
    esg-score: uint,       ;; 0-100
    violation-count: uint,
    active: bool
  }
)

;; Shipment records
(define-map shipments
  { shipment-id: uint }
  {
    supplier: principal,
    description: (string-ascii 128),
    current-stage: uint,
    esg-score: uint,       ;; aggregated score for current stage
    validation-count: uint,;; number of validators who have signed off
    finalized: bool
  }
)

;; Tracks which validators have signed off on a given shipment stage
(define-map stage-validations
  { shipment-id: uint, stage: uint, validator: principal }
  { approved: bool, score: uint }
)

;; Compliance alerts logged on-chain
(define-map compliance-alerts
  { alert-id: uint }
  {
    shipment-id: uint,
    supplier: principal,
    stage: uint,
    reason: (string-ascii 128),
    block-height: uint
  }
)

(define-data-var shipment-nonce uint u0)
(define-data-var alert-nonce    uint u0)

;; ============================================================
;; Private Helpers
;; ============================================================

(define-private (is-contract-owner)
  (is-eq tx-sender CONTRACT-OWNER)
)

(define-private (get-validator-role (who principal))
  (match (map-get? validators { validator: who })
    entry (get role entry)
    u0
  )
)

(define-private (is-active-validator (who principal))
  (match (map-get? validators { validator: who })
    entry (get active entry)
    false
  )
)

;; Compute new ESG score as a running average
(define-private (compute-new-score (current-score uint) (count uint) (new-score uint))
  (/ (+ (* current-score count) new-score) (+ count u1))
)

;; Apply graduated penalty: reduce supplier ESG by severity points (floor 0)
(define-private (apply-penalty (supplier principal) (severity uint))
  (match (map-get? suppliers { supplier: supplier })
    entry
      (let (
        (current (get esg-score entry))
        (penalized (if (> severity current) u0 (- current severity)))
      )
        (map-set suppliers
          { supplier: supplier }
          (merge entry {
            esg-score: penalized,
            violation-count: (+ (get violation-count entry) u1)
          })
        )
        true
      )
    false
  )
)

(define-private (log-alert (shipment-id uint) (supplier principal) (stage uint) (reason (string-ascii 128)))
  (let ((id (var-get alert-nonce)))
    (map-set compliance-alerts
      { alert-id: id }
      {
        shipment-id: shipment-id,
        supplier: supplier,
        stage: stage,
        reason: reason,
        block-height: block-height
      }
    )
    (var-set alert-nonce (+ id u1))
    id
  )
)

;; ============================================================
;; Admin Functions
;; ============================================================

;; Register a validator with a specific role
(define-public (register-validator (who principal) (role uint))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (asserts! (and (>= role u1) (<= role u4)) ERR-INVALID-SCORE)
    (asserts! (is-none (map-get? validators { validator: who })) ERR-ALREADY-REGISTERED)
    (map-set validators { validator: who } { role: role, active: true })
    (ok true)
  )
)

;; Deactivate a validator
(define-public (deactivate-validator (who principal))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (match (map-get? validators { validator: who })
      entry
        (begin
          (map-set validators { validator: who } (merge entry { active: false }))
          (ok true)
        )
      ERR-NOT-AUTHORIZED
    )
  )
)

;; Register a new supplier
(define-public (register-supplier (supplier principal) (name (string-ascii 64)))
  (begin
    (asserts! (is-contract-owner) ERR-NOT-AUTHORIZED)
    (asserts! (is-none (map-get? suppliers { supplier: supplier })) ERR-ALREADY-REGISTERED)
    (map-set suppliers
      { supplier: supplier }
      { name: name, esg-score: u80, violation-count: u0, active: true }
    )
    (ok true)
  )
)

;; ============================================================
;; Shipment Lifecycle
;; ============================================================

;; Supplier creates a new shipment
(define-public (create-shipment (description (string-ascii 128)))
  (let (
    (id (var-get shipment-nonce))
  )
    (asserts! (is-some (map-get? suppliers { supplier: tx-sender })) ERR-NOT-AUTHORIZED)
    (asserts! (get active (unwrap! (map-get? suppliers { supplier: tx-sender }) ERR-NOT-AUTHORIZED)) ERR-NOT-AUTHORIZED)
    (map-set shipments
      { shipment-id: id }
      {
        supplier: tx-sender,
        description: description,
        current-stage: STAGE-SOURCING,
        esg-score: u0,
        validation-count: u0,
        finalized: false
      }
    )
    (var-set shipment-nonce (+ id u1))
    (ok id)
  )
)

;; Validator submits an ethical compliance score for a shipment at its current stage
;; score: 0-100; below MIN-ESG-SCORE triggers a penalty alert
(define-public (submit-validation (shipment-id uint) (score uint))
  (let (
    (shipment  (unwrap! (map-get? shipments { shipment-id: shipment-id }) ERR-SHIPMENT-NOT-FOUND))
    (stage     (get current-stage shipment))
    (supplier  (get supplier shipment))
  )
    (asserts! (is-active-validator tx-sender) ERR-NOT-AUTHORIZED)
    (asserts! (not (get finalized shipment)) ERR-STAGE-NOT-READY)
    (asserts! (<= score u100) ERR-INVALID-SCORE)
    (asserts!
      (is-none (map-get? stage-validations { shipment-id: shipment-id, stage: stage, validator: tx-sender }))
      ERR-ALREADY-VALIDATED
    )

    ;; Record this validator's sign-off
    (map-set stage-validations
      { shipment-id: shipment-id, stage: stage, validator: tx-sender }
      { approved: (>= score MIN-ESG-SCORE), score: score }
    )

    ;; Update aggregated shipment score
    (let (
      (count     (get validation-count shipment))
      (new-score (compute-new-score (get esg-score shipment) count score))
      (new-count (+ count u1))
    )
      (map-set shipments
        { shipment-id: shipment-id }
        (merge shipment { esg-score: new-score, validation-count: new-count })
      )

      ;; Apply graduated penalty if this validator scored below threshold
      (if (< score MIN-ESG-SCORE)
        (begin
          (apply-penalty supplier (- MIN-ESG-SCORE score))
          (log-alert shipment-id supplier stage "Validator score below compliance threshold")
          (ok new-score)
        )
        (ok new-score)
      )
    )
  )
)

;; Advance shipment to the next stage once minimum validations are met
;; Requires at least 4 validations (one per role) and aggregate score >= MIN-ESG-SCORE
(define-public (advance-stage (shipment-id uint))
  (let (
    (shipment (unwrap! (map-get? shipments { shipment-id: shipment-id }) ERR-SHIPMENT-NOT-FOUND))
  )
    (asserts! (is-eq tx-sender (get supplier shipment)) ERR-NOT-AUTHORIZED)
    (asserts! (not (get finalized shipment)) ERR-STAGE-NOT-READY)
    (asserts! (>= (get validation-count shipment) u4) ERR-STAGE-NOT-READY)
    (asserts! (>= (get esg-score shipment) MIN-ESG-SCORE) ERR-THRESHOLD-NOT-MET)

    (let ((next-stage (+ (get current-stage shipment) u1)))
      (if (>= next-stage STAGE-DELIVERED)
        ;; Mark shipment as delivered/finalized
        (begin
          (map-set shipments
            { shipment-id: shipment-id }
            (merge shipment { current-stage: STAGE-DELIVERED, finalized: true, esg-score: u0, validation-count: u0 })
          )
          (ok STAGE-DELIVERED)
        )
        ;; Move to next stage and reset validation accumulators
        (begin
          (map-set shipments
            { shipment-id: shipment-id }
            (merge shipment { current-stage: next-stage, esg-score: u0, validation-count: u0 })
          )
          (ok next-stage)
        )
      )
    )
  )
)

;; ============================================================
;; Read-Only Functions
;; ============================================================

(define-read-only (get-shipment (shipment-id uint))
  (map-get? shipments { shipment-id: shipment-id })
)

(define-read-only (get-supplier (supplier principal))
  (map-get? suppliers { supplier: supplier })
)

(define-read-only (get-validator (who principal))
  (map-get? validators { validator: who })
)

(define-read-only (get-stage-validation (shipment-id uint) (stage uint) (validator principal))
  (map-get? stage-validations { shipment-id: shipment-id, stage: stage, validator: validator })
)

(define-read-only (get-compliance-alert (alert-id uint))
  (map-get? compliance-alerts { alert-id: alert-id })
)

(define-read-only (get-shipment-count)
  (var-get shipment-nonce)
)

(define-read-only (get-alert-count)
  (var-get alert-nonce)
)
