function unsafe(req) {
  const code = req.query.code;
  eval(code);
}
