function textOnly(req, element) {
    element.textContent = req.query.html;
}
