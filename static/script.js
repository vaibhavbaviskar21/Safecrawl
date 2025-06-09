const form = document.querySelector('form');
form.addEventListener('submit', () => {
  form.querySelector('button').innerText = 'Scanning...';
});
