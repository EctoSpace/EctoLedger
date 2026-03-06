import { writable } from "svelte/store";

/** True when the Live Observer has been opened in a separate window. */
export const observerPoppedOut = writable(false);
