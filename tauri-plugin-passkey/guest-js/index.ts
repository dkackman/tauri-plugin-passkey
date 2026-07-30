import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";

/**
 * The WebAuthn JSON types used below — `PublicKeyCredentialCreationOptionsJSON`,
 * `PublicKeyCredentialRequestOptionsJSON`, `RegistrationResponseJSON` and
 * `AuthenticationResponseJSON` — are standard DOM types, globally available to
 * any consumer compiling with the `DOM` lib. Only the union of the two response
 * types has no name in the DOM lib, so it is declared here.
 */
export type PublicKeyCredentialJSON =
  RegistrationResponseJSON | AuthenticationResponseJSON;

export type WebauthnEvent =
  | {
      type: WebauthnEventType.SelectDevice | WebauthnEventType.PresenceRequired;
    }
  | {
      type: WebauthnEventType.PinEvent;
      event: PinEvent;
    }
  | {
      type: WebauthnEventType.SelectKey;
      keys: AuthKey[];
    };

export enum WebauthnEventType {
  SelectDevice = "selectDevice",
  PresenceRequired = "presenceRequired",
  PinEvent = "pinEvent",
  SelectKey = "selectKey",
}

export type PinEvent =
  | {
      type:
        | PinEventType.PinRequired
        | PinEventType.PinAuthBlocked
        | PinEventType.PinBlocked
        | PinEventType.UvBlocked
        | PinEventType.PinIsTooShort
        | PinEventType.PinNotSet;
    }
  | {
      type: PinEventType.InvalidPin | PinEventType.InvalidUv;
      attempts_remaining?: number;
    }
  | {
      type: PinEventType.PinIsTooLong;
      max_length: number;
    };

export enum PinEventType {
  PinRequired = "pinRequired",
  InvalidPin = "invalidPin",
  PinAuthBlocked = "pinAuthBlocked",
  PinBlocked = "pinBlocked",
  InvalidUv = "invalidUv",
  UvBlocked = "uvBlocked",
  PinIsTooShort = "pinIsTooShort",
  PinIsTooLong = "pinIsTooLong",
  PinNotSet = "pinNotSet",
}

export type AuthKey = {
  id: string;
  name?: string;
  displayName?: string;
};

export const EVENT_NAME = "tauri-plugin-passkey";

/**
 * Tries to register using the native WebAuthn API.
 *
 * @param origin The origin of the request. This is used to verify the request.
 * @param options The webauthn options. This is used to create the request.
 * @returns A promise that resolves to the registration response.
 */
export async function register(
  origin: string,
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<RegistrationResponseJSON> {
  return await invoke<RegistrationResponseJSON>("plugin:passkey|register", {
    origin,
    options,
  });
}

/**
 * Tries to authenticate using the native WebAuthn API.
 *
 * @param origin The origin of the request. This is used to verify the request.
 * @param options The webauthn options. This is used to create the request.
 * @returns A promise that resolves to the authentication response.
 */
export async function authenticate(
  origin: string,
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<PublicKeyCredentialJSON> {
  return await invoke<PublicKeyCredentialJSON>("plugin:passkey|authenticate", {
    origin,
    options,
  });
}

/**
 * Sends a pin to the authenticator.
 * Only needed on Linux; PIN entry is handled natively elsewhere.
 *
 * @param pin The pin to send to the authenticator.
 * @returns A promise that resolves when the pin has been sent.
 */
export async function sendPin(pin: string): Promise<void> {
  return await invoke("plugin:passkey|send_pin", {
    pin,
  });
}

/**
 * Select a key from the list of keys received by the `selectKey` event.
 * Does nothing on windows and mobile.
 *
 * @param uv The uv to send to the authenticator.
 * @returns A promise that resolves when the uv has been sent.
 */
export async function selectKey(index: number): Promise<void> {
  return await invoke("plugin:passkey|select_key", {
    key: index,
  });
}

/**
 * Cancels the current operation.
 * Cancels the pending operation on Linux, macOS, iOS, and Android. Does nothing on Windows.
 *
 * @returns A promise that resolves when the operation has been cancelled.
 */
export async function cancel(): Promise<void> {
  return await invoke("plugin:passkey|cancel");
}

/**
 * Creates a listener for the webauthn events.
 * Events are only emitted on Linux; other platforms show native UI instead.
 *
 * @param listener The listener to call when the event is triggered.
 * @returns A promise that resolves to a function that can be used to unregister the listener.
 */
export async function registerListener(
  listener: (event: WebauthnEvent) => void
): Promise<UnlistenFn> {
  return listen(EVENT_NAME, (event) => {
    listener(event.payload as WebauthnEvent);
  });
}
