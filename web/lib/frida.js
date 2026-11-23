// Frida plugin: runs user JavaScript inside Discord through frida-gadget in script mode.
//
// Gadget: web/plugins/frida-gadget-17.27.4-android-{arm64,x86_64}.so.gz = frida-gadget-17.27.4-android-<arch>.so.xz
// from https://github.com/frida/frida/releases/tag/17.27.4, recompressed with gzip -9 so the browser can unpack it
// (DecompressionStream). sha256 of the .so: arm64 4b7d3eaf5d5a3dc605bd460a6b4d38bae5db7aeb1b09a216e22ed5886782f4b2,
// x86_64 61260e633db2189ab4655b5b28d0aaf41d3ec31337c282af27e30dc151aff881.
// Frida is licensed under the wxWindows Library Licence 3.1.
//
// Loading: apk.js renames DT_NEEDED liblog.so -> libfrg.so (the gadget, which itself needs liblog.so, so symbol
// lookup is unchanged) in the loader libplm.so, or in the host lib when the plugin runtime is off. Either way
// the gadget's constructor runs while liblibdiscord_wasm_host.so loads and,
// in script mode, runs the script synchronously before the app goes on. The gadget reads its config and the
// script straight from the APK: its own path is ".../base.apk!/lib/<abi>/libfrg.so", from which it derives
// libfrg.config.so, and Frida 17 resolves "x.apk!/entry" paths with its own zip reader. So native libs stay
// stored (extractNativeLibs=false) and nothing is extracted.
//
// Script: frida/bootstrap.js, prebuilt to web/plugins/frida-bootstrap.js (frida/build.sh; it bundles
// frida-java-bridge, which Frida 17 no longer ships) with the website's plugins prepended. The bootstrap keeps
// plugins in the app's files/phoenix-plugins/ and adds the in-app panel and the optional debug shell.

/** gadget per Android ABI dir */
export const GADGET_URLS = {
  'arm64-v8a': 'plugins/frida-gadget-17.27.4-android-arm64.so.gz',
  'armeabi-v7a': 'plugins/frida-gadget-17.27.4-android-arm.so.gz',
  'x86_64': 'plugins/frida-gadget-17.27.4-android-x86_64.so.gz',
};
export const BOOTSTRAP_URL = 'plugins/frida-bootstrap.js';
export const GADGET = 'libfrg.so'; // same length as liblog.so (DT_NEEDED rename in place)
const SCRIPT = 'libfrg.js.so';

/** gunzip; passes data through if the server already decoded it (Content-Encoding: gzip). */
export async function gunzip(u8) {
  if (u8[0] !== 0x1f || u8[1] !== 0x8b) return u8;
  const s = new Blob([u8]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(s).arrayBuffer());
}

/**
 * The gadget's script: the bootstrap (frida/bootstrap.js, built to BOOTSTRAP_URL) plus the plugins picked on
 * the website, which it copies to <files>/phoenix-plugins/ and runs from there, next to plugins added in the app.
 * Syntax is checked here so a typo fails the build instead of showing up only in the app's console.
 * @param {{name: string, code: string}[]} files
 * @param {string} bootstrap
 */
export function bundleScripts(files, bootstrap) {
  const plugins = {};
  for (const { name, code } of files) {
    try { new Function(code); } catch (e) { throw new Error(`${name}: ${e.message}`); }
    let n = name.replace(/^.*[\\/]/, '').replace(/[^\w.-]/g, '_');
    if (!n.endsWith('.js')) n += '.js';
    plugins[n] = code;
  }
  // the gadget's own load errors go nowhere on Android, so report a failing bootstrap to logcat
  return `globalThis.BUNDLED_PLUGINS = ${JSON.stringify(plugins)};\ntry {\n${bootstrap}\n} catch (e) {
  new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'), 'int', ['int', 'pointer', 'pointer'])(
    6, Memory.allocUtf8String('FridaPlugins'), Memory.allocUtf8String('bootstrap failed: ' + (e.stack || e)));
}\n`;
}

/** Files to add to native lib dir `DIR` (e.g. 'lib/arm64-v8a/'): [name, data][] */
export function fridaFiles(gadget, script, DIR) {
  const config = { interaction: { type: 'script', path: SCRIPT, on_change: 'ignore' } };
  const te = new TextEncoder();
  return [
    [DIR + GADGET, gadget],
    [DIR + GADGET.replace('.so', '.config.so'), te.encode(JSON.stringify(config))],
    [DIR + SCRIPT, te.encode(script)],
  ];
}
