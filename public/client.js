let token = null;
let socket = null;

async function register() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const res = await fetch('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  alert(res.ok ? 'Registered!' : 'Error registering.');
}

async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const res = await fetch('/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  const data = await res.json();
  if (data.token) {
    token = data.token;
    document.getElementById('login').style.display = 'none';
    document.getElementById('chat').style.display = 'block';
    connectSocket();
  } else {
    alert('Login failed');
  }
}

function connectSocket() {
  socket = io({ auth: { token } });
  socket.on('connect', () => console.log('Connected'));
  socket.on('chat message', (data) => {
    const decrypted = decryptMessage(data.message);
    const msgBox = document.getElementById('messages');
    msgBox.innerHTML += `<div><b>${data.from}:</b> ${decrypted}</div>`;
  });
}

function sendMessage() {
  const msg = document.getElementById('msgInput').value;
  socket.emit('chat message', msg);
  document.getElementById('msgInput').value = '';
}

function decryptMessage(data) {
  // client-side AES decrypt (optional)
  return data; // Keep encrypted text simple (or implement AES here)
}

document.getElementById('registerBtn').onclick = register;
document.getElementById('loginBtn').onclick = login;
document.getElementById('sendBtn').onclick = sendMessage;
