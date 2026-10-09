function unsafe(req, element) {
  const html = req.query.html;
  element.innerHTML = html;
}
