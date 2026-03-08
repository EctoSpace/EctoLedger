import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";
import { mount } from "svelte";
import App from "./App.svelte";
import "./app.css";

mount(App, { target: document.getElementById("app")! });
