import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/** Merge Tailwind class names — the `cn()` helper used by all UI components. */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
