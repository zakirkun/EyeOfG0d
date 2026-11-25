import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "EyeOfG0d",
  version: packageJson.version,
  copyright: `© ${currentYear}, EyeOfG0d.`,
  meta: {
    title: "EyeOfG0d — Autonomous Penetration Testing Console",
    description: "Console for the LLM-driven autonomous penetration testing system",
  },
};
