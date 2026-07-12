// fetch() posting user data to api.openai.com without redaction
async function analyzeData(userData) {
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { 'Authorization': 'Bearer ' + process.env.OPENAI_API_KEY },
    body: JSON.stringify({
      model: 'gpt-4',
      messages: [{ role: 'user', content: userData.email + ' ' + userData.phone }],
    }),
  });
  return response.json();
}