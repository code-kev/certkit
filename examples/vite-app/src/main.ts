import './style.css';

const app = document.querySelector<HTMLElement>('#app');
if (!app) throw new Error('Missing #app root');

const header = document.createElement('header');
header.className = 'topbar';
header.innerHTML =
  '<a class="brand" href="#">certkit<span class="brand-tag">demo</span></a><span class="local">LOCAL DEVELOPMENT</span>';

const main = document.createElement('main');
main.className = 'content';
main.innerHTML = `
  <p class="eyebrow">LOCAL HTTPS · VITE</p>
  <h1>Build locally.<br><span class="accent">Connect securely.</span></h1>
  <p class="intro">certkit gives your development server a locally trusted certificate using the same package that creates and manages your CA.</p>
  <div class="card">
    <div class="card-heading"><span class="dot"></span><span>Example HTTPS configuration</span><span class="port">:5173</span></div>
    <div class="address"><span class="lock">⌑</span> https://localhost:5173</div>
    <div class="rule"></div>
    <p>Vite plugin: <code>certkit()</code></p>
    <p>Certificate names: <code>localhost</code>, <code>127.0.0.1</code>, <code>::1</code></p>
  </div>
  <p class="note"><strong>First run?</strong> Install the local CA with <code>certkit install</code> before starting Vite.</p>
`;

const footer = document.createElement('footer');
footer.textContent = 'A local development example · Not for production use';
app.replaceChildren(header, main, footer);
