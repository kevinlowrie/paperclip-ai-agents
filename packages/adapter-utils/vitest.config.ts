import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    name: "@paperclipai/adapter-utils",
    exclude: [...configDefaults.exclude, "src/ssh-private-input.test.ts"],
  },
});
