// RR02 — app desktop macOS minimale (Swift + WKWebView)
// Affiche l'overlay existant (http://127.0.0.1:8789/) dans une fenetre native
// toujours au-dessus du jeu. Cmd+T = au-dessus, Cmd+R = recharger, Cmd+Q = quitter.
import Cocoa
import WebKit

let OVERLAY = "http://127.0.0.1:8789/"

final class AppDelegate: NSObject, NSApplicationDelegate, WKNavigationDelegate {
    var win: NSWindow!
    var web: WKWebView!
    var onTop = true

    func applicationDidFinishLaunching(_ note: Notification) {
        let rect = NSRect(x: 0, y: 0, width: 560, height: 620)
        win = NSWindow(contentRect: rect,
                       styleMask: [.titled, .closable, .resizable, .miniaturizable, .fullSizeContentView],
                       backing: .buffered, defer: false)
        win.title = "RR02"
        win.titlebarAppearsTransparent = true
        win.titleVisibility = .hidden
        win.backgroundColor = NSColor(calibratedRed: 0.04, green: 0.06, blue: 0.08, alpha: 1.0)
        win.isMovableByWindowBackground = true
        win.level = .floating
        win.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        win.minSize = NSSize(width: 360, height: 360)

        let cfg = WKWebViewConfiguration()
        cfg.preferences.setValue(true, forKey: "developerExtrasEnabled")
        web = WKWebView(frame: rect, configuration: cfg)
        web.navigationDelegate = self
        web.setValue(false, forKey: "drawsBackground")
        win.contentView = web
        win.center()
        win.makeKeyAndOrderFront(nil)

        buildMenu()
        load()
        NSApp.activate(ignoringOtherApps: true)
    }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem()
        main.addItem(appItem)
        let m = NSMenu()
        let t = NSMenuItem(title: "Toujours au-dessus", action: #selector(toggleTop), keyEquivalent: "t"); t.target = self
        let r = NSMenuItem(title: "Recharger", action: #selector(reload), keyEquivalent: "r"); r.target = self
        let q = NSMenuItem(title: "Quitter", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        m.addItem(t); m.addItem(r); m.addItem(NSMenuItem.separator()); m.addItem(q)
        appItem.submenu = m
        NSApp.mainMenu = main
    }

    func load() { web.load(URLRequest(url: URL(string: OVERLAY)!)) }
    @objc func toggleTop() { onTop.toggle(); win.level = onTop ? .screenSaver : .normal }
    @objc func reload() { load() }

    // telemetrie : ce que la webview affiche vraiment -> /tmp/rr02_app.log
    func webView(_ w: WKWebView, didFinish nav: WKNavigation!) {
        Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            let js = """
            JSON.stringify({vw:innerWidth,vh:innerHeight,
              cw:(document.querySelector('canvas')||{width:-1}).width,
              ch:(document.querySelector('canvas')||{height:-1}).height,
              n:(typeof data!=='undefined'&&data.players?data.players.length:-1),
              it:(typeof data!=='undefined'&&data.items?data.items.length:-1),
              age:(typeof data!=='undefined'&&data.ts?(Date.now()/1000-data.ts).toFixed(1):-1),
              rot:(typeof rotTgt!=='undefined'?rotTgt.toFixed(2):'-')})
            """
            w.evaluateJavaScript(js) { res, err in
                let line = String(format: "%.2f %@%@\n", Date().timeIntervalSince1970,
                                  (res as? String) ?? "nil", err.map { " ERR:" + String(describing: $0) } ?? "")
                if let fh = FileHandle(forWritingAtPath: "/tmp/rr02_app.log") {
                    fh.seekToEndOfFile(); fh.write(line.data(using: .utf8)!); try? fh.close()
                } else { try? line.write(toFile: "/tmp/rr02_app.log", atomically: true, encoding: .utf8) }
            }
        }
    }

    func webView(_ w: WKWebView, didFailProvisionalNavigation nav: WKNavigation!, withError err: Error) {
        let html = """
        <body style="background:#0b0f14;color:#e6edf3;font:14px -apple-system;padding:26px">
        <b>serve.py injoignable</b><br><br>Lance-le puis Cmd+R :<br>
        <code style="color:#4ade80">cd "/Users/mac/Desktop/02 - Reverse &amp; Jeux/RR02" &amp;&amp; python3 serve.py</code>
        </body>
        """
        w.loadHTMLString(html, baseURL: nil)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
