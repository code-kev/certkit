import './style.css';

const app = document.querySelector<HTMLElement>('#app');
if (!app) throw new Error('Missing #app root');

app.innerHTML = `
  <header class="topbar">
    <a class="brand" href="#">certkit</a>
    <span class="topbar-label">VITE EXAMPLE</span>
  </header>
  <main class="content">
    <section class="intro" aria-labelledby="page-title">
      <p class="eyebrow">LOCAL DEVELOPMENT / HTTPS</p>
      <h1 id="page-title">Local HTTPS<br>for Vite.</h1>
      <p class="summary">certkit gives your development server a local certificate, managed by the same package that creates your local CA.</p>
    </section>
    <section class="setup" aria-labelledby="setup-title">
      <div class="section-heading">
        <p class="eyebrow">01 / SETUP</p>
        <h2 id="setup-title">Install the local CA, then start Vite.</h2>
      </div>
      <pre class="command"><code><span class="prompt"># repository root</span>
pnpm install
pnpm build
node dist/cli/index.js install

<span class="prompt"># then, from the repository root</span>
cd examples/vite-app
pnpm exec vite</code></pre>
      <p class="setup-note">Build certkit first. Install the local CA once for the current user; trust behavior depends on the operating system and browser.</p>
    </section>
    <section class="details" aria-label="Example configuration">
      <div class="detail">
        <p class="eyebrow">02 / ADDRESS</p>
        <p class="value"><code>https://localhost:5173</code></p>
        <p class="detail-note">Illustrative URL and port</p>
      </div>
      <div class="detail">
        <p class="eyebrow">03 / VITE PLUGIN</p>
        <p class="value"><code>certkit()</code></p>
        <p class="detail-note">HTTPS enabled in the example config</p>
      </div>
      <div class="detail">
        <p class="eyebrow">04 / CERTIFICATE NAMES</p>
        <p class="value names"><code>localhost</code><code>127.0.0.1</code><code>::1</code></p>
        <p class="detail-note">DNS and IP subject alternative names</p>
      </div>
    </section>
  </main>
  <footer><span>certkit / local development example</span><span>Not for production use</span></footer>
`;
