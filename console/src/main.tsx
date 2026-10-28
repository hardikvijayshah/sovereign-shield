import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";

import { Api } from "./api";
import { App, NoRole } from "./App";
import { Auth, SignInRequiredError } from "./auth";
import { loadConfig } from "./config";
import { SessionContext } from "./session";
import "./styles.css";

const root = createRoot(document.getElementById("root") as HTMLElement);

async function start(): Promise<void> {
  const config = await loadConfig();
  const auth = new Auth(config);

  if (window.location.pathname === "/callback") {
    const returnTo = await auth.completeSignIn(window.location.search);
    // Drop the authorization code from the address bar and history.
    window.history.replaceState(null, "", returnTo);
  }

  if (!(await auth.accessToken())) {
    await auth.signIn(window.location.pathname + window.location.search);
  }

  const api = new Api(config, auth);
  const configuration = await api.configuration();
  if (configuration.caller.roles.length === 0) {
    root.render(<NoRole />);
    return;
  }

  root.render(
    <StrictMode>
      <SessionContext.Provider value={{ api, auth, configuration }}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </SessionContext.Provider>
    </StrictMode>,
  );
}

start().catch((error: unknown) => {
  if (error instanceof SignInRequiredError) {
    return; // The browser is navigating to the hosted sign-in page.
  }
  root.render(
    <div className="centered">
      <h1>Sovereign Shield</h1>
      <p className="error" role="alert">
        {error instanceof Error ? error.message : "The console could not start."}
      </p>
      <a href="/">Try again</a>
    </div>,
  );
});
