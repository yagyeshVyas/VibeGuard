// Client-side XSS: innerHTML with request-derived input
const userInput = new URLSearchParams(window.location.search).get('name');
document.getElementById('output').innerHTML = userInput;