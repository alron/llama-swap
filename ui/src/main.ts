import "./index.css";
import App from "./App.svelte";
import { mount } from "svelte";
import { watchSession } from "./lib/session";

watchSession();

const app = mount(App, {
  target: document.getElementById("app")!,
});

export default app;
