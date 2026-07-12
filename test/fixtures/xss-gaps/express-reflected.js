// Express XSS: res.send with innerHTML on server-rendered content
app.get('/profile', (req, res) => {
  const name = req.query.name;
  res.send(`<div id="profile">${name}</div>`);
});