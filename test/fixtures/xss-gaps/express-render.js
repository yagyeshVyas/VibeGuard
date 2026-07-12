// Express XSS: res.render with unescaped user input in template
app.get('/search', (req, res) => {
  const q = req.query.q;
  res.render('results', { query: q });
});