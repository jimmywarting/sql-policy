/**
 * @typedef {'SYNTAX' | 'UNSUPPORTED' | 'TOO_LONG' | 'PARAMS' | 'TABLE_DENIED' |
 *   'COLUMN_DENIED' | 'OPERATION_DENIED' | 'FUNCTION_DENIED' | 'VERIFY_FAILED'} PolicyErrorCode
 */

/** Thrown whenever a query is not allowed or cannot be checked. */
class PolicyError extends Error {
  name = 'PolicyError'

  /**
   * @param {PolicyErrorCode} code
   * @param {string} message
   * @param {Record<string, unknown>} [details]
   */
  constructor (code, message, details = {}) {
    super(message)
    this.code = code
    this.details = details
  }
}

export {
  PolicyError
}