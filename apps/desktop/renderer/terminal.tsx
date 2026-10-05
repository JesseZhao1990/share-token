import { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import { api } from './api.js';
import { terminalSessionStatus } from './session-view.js';
export function TerminalWindow() {
  const element = useRef<HTMLDivElement>(null); const [status, setStatus] = useState('正在连接本机会话');
  useEffect(() => {
    const term = new Terminal({ cursorBlink: true, fontFamily: 'Menlo, monospace', fontSize: 13, scrollback: 3000, allowProposedApi: false, allowTransparency: false, theme: { background: '#17231e', foreground: '#e0e8dd', cursor: '#b5d39d', selectionBackground: '#42644f' } });
    const fit = new FitAddon(); term.loadAddon(fit); term.open(element.current!);
    // OSC clipboard commands are consumed, never forwarded to the operating system.
    const clipboard = term.parser.registerOscHandler(52, () => true);
    const input = term.onData(data => { void api.terminalWrite(data).catch(error => setStatus(String(error.message))); });
    let attached = false; const staged: { data: string; sequence: number }[] = []; let disposed = false;
    let latestSession: import('./api.js').LocalSession | undefined;
    const unsubscribe = api.onEvent(event => {
      if (event.type === 'terminal.data') { if (attached) term.write(event.data ?? ''); else staged.push({ data: event.data ?? '', sequence: event.sequence ?? 0 }); }
      if (event.type === 'terminal.exit') setStatus(`Codex 已退出 · 退出码 ${event.exitCode ?? '未知'}`);
      if (event.type === 'session.updated' && event.session) { latestSession = event.session; setStatus(terminalSessionStatus(latestSession)); }
    });
    void api.terminalAttach().then(result => { if (disposed) return; term.write(result.backlog); for (const event of staged) if (event.sequence > result.sequence) term.write(event.data); staged.length = 0; attached = true; setStatus(terminalSessionStatus(latestSession ?? result.session)); fit.fit(); void api.terminalResize(term.cols, term.rows).catch(() => {}); term.focus(); }).catch(error => setStatus(error.message));
    const observer = new ResizeObserver(() => { if (!attached || disposed) return; fit.fit(); void api.terminalResize(term.cols, term.rows).catch(() => {}); }); observer.observe(element.current!);
    return () => { disposed = true; unsubscribe(); observer.disconnect(); clipboard.dispose(); input.dispose(); term.dispose(); };
  }, []);
  return <div className="terminal-window"><header className="drag"><strong>共享token / Codex</strong><span>{status}</span></header><div ref={element} className="terminal-mount"/></div>;
}
