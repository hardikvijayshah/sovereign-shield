import { createContext, useContext } from "react";

import type { Api } from "./api";
import type { Auth } from "./auth";
import type { Configuration } from "./types";

export interface ConsoleSession {
  api: Api;
  auth: Auth;
  configuration: Configuration;
}

export const SessionContext = createContext<ConsoleSession | null>(null);

export function useSession(): ConsoleSession {
  const session = useContext(SessionContext);
  if (!session) {
    throw new Error("useSession must be used inside SessionContext.");
  }
  return session;
}

/** Presentation only: the API enforces every action independently. */
export function useCan(action: string): boolean {
  return useSession().configuration.caller.allowedActions.includes(action);
}
