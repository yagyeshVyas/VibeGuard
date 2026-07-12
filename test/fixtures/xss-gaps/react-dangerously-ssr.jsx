// React: dangerouslySetInnerHTML with request data (SSR context)
import { dangerouslySetInnerHTML } from 'react';
app.get('/page', (req, res) => {
  const html = req.body.content;
  const el = <div dangerouslySetInnerHTML={{__html: html}} />;
  res.send(renderToString(el));
});