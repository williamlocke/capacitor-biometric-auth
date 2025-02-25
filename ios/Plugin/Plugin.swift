import Capacitor
import Foundation
import LocalAuthentication

private let kReason = "reason"
private let kMissingFaceIDUsageEntry = "The device supports Face ID, but NSFaceIDUsageDescription is not in Info.plist."

@objc(BiometricAuthNative)
public class BiometricAuthNative: CAPPlugin {
  let biometryErrorCodeMap: [Int: String] = [
    0: "",
    LAError.appCancel.rawValue: "appCancel",
    LAError.authenticationFailed.rawValue: "authenticationFailed",
    LAError.invalidContext.rawValue: "invalidContext",
    LAError.notInteractive.rawValue: "notInteractive",
    LAError.passcodeNotSet.rawValue: "passcodeNotSet",
    LAError.systemCancel.rawValue: "systemCancel",
    LAError.userCancel.rawValue: "userCancel",
    LAError.userFallback.rawValue: "userFallback",
    LAError.biometryLockout.rawValue: "biometryLockout",
    LAError.biometryNotAvailable.rawValue: "biometryNotAvailable",
    LAError.biometryNotEnrolled.rawValue: "biometryNotEnrolled"
  ]

  struct CheckDeviceBiometryResult {
    let isAvailable: Bool
    let biometryType: LABiometryType.RawValue
    let biometryTypes: JSArray
    let reason: String
    let code: String
  }

  /**
   * Plugin call checkBiometry()
   */
  @objc func checkBiometry(_ call: CAPPluginCall) {
    print("[BiometricAuthNative] Checking biometry availability...")
    let checkResult = checkDeviceBiometry()
    print("[BiometricAuthNative] Biometry check result - isAvailable: \(checkResult.isAvailable), type: \(checkResult.biometryType), reason: \(checkResult.reason)")

    call.resolve([
      "isAvailable": checkResult.isAvailable,
      "biometryType": checkResult.biometryType,
      "biometryTypes": checkResult.biometryTypes,
      "reason": checkResult.reason,
      "code": checkResult.code
    ])
  }

  /**
   * Check the device's availability and type of biometric authentication.
   */
  func checkDeviceBiometry() -> CheckDeviceBiometryResult {
    print("[BiometricAuthNative] Performing biometry check...")
    let context = LAContext()
    var error: NSError?
    var available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    var reason = ""
    var errorCode = ""

    if available, context.biometryType == .faceID {
      let entry = Bundle.main.infoDictionary?["NSFaceIDUsageDescription"] as? String
      if entry == nil {
        available = false
        reason = kMissingFaceIDUsageEntry
        errorCode = biometryErrorCodeMap[LAError.biometryNotAvailable.rawValue] ?? ""
        print("[BiometricAuthNative] Face ID usage description missing in Info.plist.")
      }
    } else if !available, let error = error {
      reason = error.localizedDescription
      if let failureReason = error.localizedFailureReason {
        reason = "\(reason): \(failureReason)"
      }
      errorCode = biometryErrorCodeMap[error.code] ?? biometryErrorCodeMap[LAError.biometryNotAvailable.rawValue] ?? ""
      print("[BiometricAuthNative] Biometry unavailable: \(reason)")
    }

    var types = JSArray()
    types.append(context.biometryType.rawValue)

    print("[BiometricAuthNative] Biometry available: \(available), Type: \(context.biometryType.rawValue)")
    
    return CheckDeviceBiometryResult(
      isAvailable: available,
      biometryType: context.biometryType.rawValue,
      biometryTypes: types,
      reason: reason,
      code: errorCode
    )
  }

  /**
   * Prompt the user for authentication.
   */
  @objc func authenticate(_ call: CAPPluginCall) {
    print("[BiometricAuthNative] Starting authentication process...")
    
    let checkResult = checkDeviceBiometry()
    if !checkResult.isAvailable {
      print("[BiometricAuthNative] Biometry is not available. Falling back to PIN entry...");
    }

    var reason: String
    if let option = call.getString(kReason), !option.isEmpty {
      reason = option
    } else {
      reason = "Access requires authentication"
    }

    let context = LAContext()
    context.localizedFallbackTitle = call.getString("iosFallbackTitle") ?? "Enter Passcode"
    context.localizedCancelTitle = call.getString("cancelTitle")
    context.touchIDAuthenticationAllowableReuseDuration = 0

    let allowDeviceCredential = call.getBool("allowDeviceCredential") ?? false
      let policy: LAPolicy = .deviceOwnerAuthentication


    if allowDeviceCredential,
       let fallbackTitle = context.localizedFallbackTitle,
       fallbackTitle.isEmpty {
      context.localizedFallbackTitle = nil
    }

    print("[BiometricAuthNative] Initiating Face ID/Touch ID authentication...")

    context.evaluatePolicy(policy, localizedReason: reason) { success, error in
      if success {
        print("[BiometricAuthNative] Authentication successful")
        call.resolve()
      } else {
        if let policyError = error as? LAError {
          let code = self.biometryErrorCodeMap[policyError.code.rawValue]
         
          call.reject(policyError.localizedDescription, code)
        } else {
          print("[BiometricAuthNative] Unknown authentication error occurred.")
          call.reject("An unknown error occurred.", self.biometryErrorCodeMap[LAError.authenticationFailed.rawValue])
        }
      }
    }
  }
}
