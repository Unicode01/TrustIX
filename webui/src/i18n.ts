export type Lang = "zh" | "en";
export type Dictionary = Record<string, string>;

export function preferredLang(defaultLang?: string): Lang {
  if (String(defaultLang || "").toLowerCase().startsWith("zh")) {
    return "zh";
  }
  const nav = (navigator.language || navigator.languages?.[0] || "en").toLowerCase();
  return nav.startsWith("zh") ? "zh" : "en";
}

export function normalizeLang(raw: string | undefined): Lang {
  return String(raw || "").toLowerCase().startsWith("zh") ? "zh" : "en";
}

export async function loadDictionary(lang: Lang): Promise<Dictionary> {
  for (const path of [`/assets/i18n/${lang}.json`, `/i18n/${lang}.json`]) {
    const response = await fetch(path, { cache: "no-cache" });
    if (response.ok) {
      return response.json();
    }
  }
  throw new Error(`load locale ${lang}`);
}
