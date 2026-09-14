// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#if os(iOS)

  import AuthenticationServices
  import Foundation
  import UIKit
  import WebKit

  /// A Class responsible for presenting URL via ASWebAuthenticationSession or WKWebView.
  class AuthURLPresenter: NSObject,
    AuthWebViewControllerDelegate, ASWebAuthenticationPresentationContextProviding {
    /// Presents an URL to interact with user.
    /// - Parameter url: The URL to present.
    /// - Parameter uiDelegate: The UI delegate to present view controller.
    /// - Parameter callbackScheme: The app's custom URL scheme that the identity provider
    /// redirects back to. meter.me change (MM-8209): `ASWebAuthenticationSession` resolves the
    /// callback itself and so has to be told the scheme. Pass the empty string when the app
    /// has none; this path then resolves no callback of its own.
    /// - Parameter completion: A block to be called either synchronously if the presentation fails
    /// to start, or asynchronously in future on an unspecified thread once the presentation
    /// finishes.
    func present(_ url: URL,
                 uiDelegate: AuthUIDelegate?,
                 callbackScheme: String,
                 callbackMatcher: @escaping (URL?) -> Bool,
                 completion: @escaping (URL?, Error?) -> Void) {
      if isPresenting {
        // Unable to start a new presentation on top of another.
        // Invoke the new completion closure and leave the old one as-is
        // to be invoked when the presentation finishes.
        DispatchQueue.main.async {
          completion(nil, AuthErrorUtils.webContextCancelledError(message: nil))
        }
        return
      }
      isPresenting = true
      self.callbackMatcher = callbackMatcher
      self.completion = completion
      DispatchQueue.main.async {
        self.uiDelegate = uiDelegate ?? AuthDefaultUIDelegate.defaultUIDelegate()
        #if targetEnvironment(macCatalyst)
          self.webViewController = AuthWebViewController(url: url, delegate: self)
          if let webViewController = self.webViewController {
            let navController = UINavigationController(rootViewController: webViewController)
            navController.modalPresentationStyle = .fullScreen
            if let fakeUIDelegate = self.fakeUIDelegate {
              fakeUIDelegate.present(navController, animated: true)
            } else {
              self.uiDelegate?.present(navController, animated: true)
            }
          }
        #else
          // meter.me change against upstream 12.19.1. Upstream presents this URL in an
          // SFSafariViewController. Measured on a physical iPhone 16e, iOS 26.6.2, with
          // Safari's "Prevent Cross-Site Tracking" on, which is the default: the FIRST
          // presentation after each app launch returns from the identity provider to
          // Firebase's hosted handler page showing "Unable to process request due to
          // missing initial state", because the handler cannot read back the descriptor
          // it wrote to sessionStorage on the outbound leg. The second attempt in the same
          // app launch succeeds, and with the setting off the first attempt succeeds.
          // Upstream issue: https://github.com/firebase/firebase-ios-sdk/issues/16277.
          //
          // ASWebAuthenticationSession with prefersEphemeralWebBrowserSession asks the
          // browser not to share cookies or other browsing data with the normal Safari
          // session, which is the one lever that reaches the storage the handler loses.
          // MEASURED 2026-09-15 on a physical iPhone, iOS 26.6.2: it works. The handler keeps
          // its state and the first attempt of a launch now reaches the identity provider and
          // completes there. The flag has no effect unless it is set before start(), and
          // start() runs here on the main thread.
          //
          // The flag is READ FROM THE APP'S Info.plist rather than hardcoded, so a build can
          // test the other browser mode without repatching this SDK. Absent means ephemeral,
          // which is the mode the fix needs. The trade-off the key selects is recorded beside
          // the key in the app's own config.
          //
          // CALLBACK DELIVERY, and the first version of this change got it wrong.
          // callbackURLScheme was nil, on the reasoning that the provider's redirect would
          // reach the app through its own URL scheme and Auth.canHandle(_:) exactly as
          // upstream. MEASURED THE SAME DAY: on iOS 26 it does not. The handler navigated to
          // the app's custom scheme, iOS did not open the app, and the session ended with an
          // error, so every attempt died as "The interaction was cancelled by the user" AFTER
          // the person had already signed in to Microsoft. The scheme is therefore PASSED, the
          // session resolves the callback itself, and the URL it hands back is fed through
          // canHandle(url:), which is the SAME path an app-delegate URL open drives: the
          // callbackMatcher and finishPresentation run unchanged.
          //
          // Apple requires a CUSTOM scheme here and rejects http, https and an empty string.
          // Both callers build one from the reversed OAuth client id or "app-<googleAppID>",
          // which qualify; PhoneAuthProvider leaves it EMPTY when the app carries neither, and
          // nil is the only honest value in that case.
          //
          // ASWebAuthenticationSession has no view controller: it presents itself from a
          // window anchor. The uiDelegate is therefore BYPASSED on this path, for both
          // presentation and dismissal, and a caller-supplied uiDelegate has no effect here.
          // It still presents and dismisses the macCatalyst WKWebView path above.
          //
          // Upstream's SFSafariViewController delegate callback checked `controller ==
          // self.safariViewController`, so a callback belonging to a FINISHED presentation
          // could not end a later one. That identity check is kept rather than a bare "is any
          // session active" test. The session is held in a weak local, captured by the closure
          // and assigned immediately after it, because capturing the session strongly inside
          // its own completion handler would retain it forever.
          weak var presentedSession: ASWebAuthenticationSession?
          let session = ASWebAuthenticationSession(
            url: url,
            callbackURLScheme: callbackScheme.isEmpty ? nil : callbackScheme
          ) { [weak self] callbackURL, error in
            guard let self, let presentedSession else { return }
            kAuthGlobalWorkQueue.async {
              guard self.authSession === presentedSession else { return }
              // The session has ended either way, and can be neither cancelled nor dismissed
              // again, so it is dropped before finishing.
              self.authSession = nil
              guard let callbackURL else {
                self.finishPresentation(withURL: nil,
                                        error: Self.webError(fromSessionError: error))
                return
              }
              // canHandle runs the callbackMatcher and calls finishPresentation on a match.
              if self.canHandle(url: callbackURL) { return }
              // The matcher rejected the callback. Nothing else is left to finish this
              // presentation, so the caller would otherwise wait forever.
              self.finishPresentation(
                withURL: nil,
                error: AuthErrorUtils.error(
                  code: .webInternalError,
                  message: "The sign-in callback did not match the request that started it."
                )
              )
            }
          }
          presentedSession = session
          session.prefersEphemeralWebBrowserSession = Self.prefersEphemeralWebSession
          session.presentationContextProvider = self
          self.authSession = session
          if !session.start() {
            // start() returning false does not call the completion handler, so the caller
            // would otherwise wait forever. It is a failure to present, NOT a person
            // cancelling, so it does not borrow the cancel error.
            self.authSession = nil
            kAuthGlobalWorkQueue.async {
              self.finishPresentation(
                withURL: nil,
                error: AuthErrorUtils.error(
                  code: .webInternalError,
                  message: "The sign-in browser session could not be started."
                )
              )
            }
          }
        #endif
      }
    }

    /// Determines if a URL was produced by the currently presented URL.
    /// - Parameter url: The URL to handle.
    /// - Returns: Whether the URL could be handled or not.
    func canHandle(url: URL) -> Bool {
      if isPresenting,
         let callbackMatcher = callbackMatcher,
         callbackMatcher(url) {
        finishPresentation(withURL: url, error: nil)
        return true
      }
      return false
    }

    // MARK: ASWebAuthenticationPresentationContextProviding

    @MainActor
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
      // The SDK has no key window helper. AuthDefaultUIDelegate walks the same scenes but
      // returns a view controller, and it reaches UIApplication through a selector so that
      // the file still compiles for app extensions. Both are repeated here because
      // ASWebAuthenticationSession needs a window and not a view controller.
      let sel = NSSelectorFromString("sharedApplication")
      guard UIApplication.responds(to: sel),
            let rawApplication = UIApplication.perform(sel),
            let application = rawApplication.takeUnretainedValue() as? UIApplication else {
        return ASPresentationAnchor()
      }
      for scene in application.connectedScenes {
        guard let windowScene = scene as? UIWindowScene else { continue }
        for window in windowScene.windows where window.isKeyWindow {
          return window
        }
      }
      return ASPresentationAnchor()
    }

    // MARK: AuthWebViewControllerDelegate

    func webViewControllerDidCancel(_ controller: AuthWebViewController) {
      kAuthGlobalWorkQueue.async {
        if self.webViewController == controller {
          self.finishPresentation(withURL: nil,
                                  error: AuthErrorUtils.webContextCancelledError(message: nil))
        }
      }
    }

    func webViewController(_ controller: AuthWebViewController, canHandle url: URL) -> Bool {
      var result = false
      kAuthGlobalWorkQueue.sync {
        if self.webViewController == controller {
          result = self.canHandle(url: url)
        }
      }
      return result
    }

    func webViewController(_ controller: AuthWebViewController,
                           didFailWithError error: Error) {
      kAuthGlobalWorkQueue.async {
        if self.webViewController == controller {
          self.finishPresentation(withURL: nil, error: error)
        }
      }
    }

    /// Whether or not some web-based content is being presented.
    ///
    /// Accesses to this property are serialized on the global Auth work queue
    /// and thus this variable should not be read or written outside of the work queue.
    private var isPresenting: Bool = false

    /// The callback URL matcher for the current presentation, if one is active.
    private var callbackMatcher: ((URL) -> Bool)?

    /// The `ASWebAuthenticationSession` used for the current presentation, if any.
    private var authSession: ASWebAuthenticationSession?

    /// The `AuthWebViewController` used for the current presentation, if any.
    private var webViewController: AuthWebViewController?

    /// The UIDelegate used to present the macCatalyst web view. It is NOT used on iOS, where
    /// ASWebAuthenticationSession presents itself from a window anchor.
    var uiDelegate: AuthUIDelegate?

    /// The completion handler for the current presentation, if one is active.
    ///
    /// Accesses to this variable are serialized on the global Auth work queue
    /// and thus this variable should not be read or written outside of the work queue.
    ///
    /// This variable is also used as a flag to indicate a presentation is active.
    var completion: ((URL?, Error?) -> Void)?

    /// Test-only option to validate the calls to the uiDelegate.
    var fakeUIDelegate: AuthUIDelegate?

    // MARK: Private methods

    /// Whether the auth sheet asks the browser for an ephemeral session, read from the app's
    /// Info.plist key `MeterMeAuthEphemeralWebSession`. meter.me change (MM-8209). An absent
    /// or non-boolean value means true, which is the mode that cures the handler's lost state.
    private static var prefersEphemeralWebSession: Bool {
      Bundle.main.object(forInfoDictionaryKey: "MeterMeAuthEphemeralWebSession") as? Bool ?? true
    }

    /// Maps an `ASWebAuthenticationSession` completion error onto the closest error this SDK
    /// already produces for a web sign-in. meter.me change (MM-8209): a dismissed sheet is a
    /// cancel, but a presentation context that was never provided is a fault in how this SDK
    /// drove the session, and reporting that as a cancel hides it behind a person's action.
    private static func webError(fromSessionError error: Error?) -> Error {
      guard let error else {
        // No callback and no error is the session ending with no result, which is what the
        // SFSafariViewController "Done" button produced upstream.
        return AuthErrorUtils.webContextCancelledError(message: nil)
      }
      let nsError = error as NSError
      if nsError.domain == ASWebAuthenticationSessionErrorDomain,
         nsError.code == ASWebAuthenticationSessionError.Code.canceledLogin.rawValue {
        return AuthErrorUtils.webContextCancelledError(message: nil)
      }
      return AuthErrorUtils.error(code: .webInternalError, message: error.localizedDescription)
    }

    private func finishPresentation(withURL url: URL?, error: Error?) {
      callbackMatcher = nil
      let uiDelegate = self.uiDelegate
      self.uiDelegate = nil
      let completion = self.completion
      self.completion = nil
      let authSession = self.authSession
      self.authSession = nil
      let webViewController = self.webViewController
      self.webViewController = nil
      if let authSession {
        // The session is still on screen. This is the success path: canHandle(url:) matched
        // the callback the app received through its own URL scheme, and cancel() is what
        // dismisses an ASWebAuthenticationSession.
        DispatchQueue.main.async {
          authSession.cancel()
          self.isPresenting = false
          if let completion {
            completion(url, error)
          }
        }
      } else if webViewController != nil {
        DispatchQueue.main.async {
          uiDelegate?.dismiss(animated: true) {
            self.isPresenting = false
            if let completion {
              completion(url, error)
            }
          }
        }
      } else {
        isPresenting = false
        if let completion {
          completion(url, error)
        }
      }
    }
  }
#endif
