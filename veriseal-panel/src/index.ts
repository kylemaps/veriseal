import { ExtensionContext } from "@foxglove/extension";

import { initSealCheckPanel } from "./SealCheckPanel";

export function activate(extensionContext: ExtensionContext): void {
  extensionContext.registerPanel({ name: "Seal Check", initPanel: initSealCheckPanel });
}
