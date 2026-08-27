// Rows added here are submitted as adjacent claim_key / claim_value pairs and
// matched up server side in document order, so keep the two inputs together.
function addClaim() {
    var container = document.getElementById("extra-claims");

    var row = document.createElement("div");
    row.className = "theme-form-row idp-claim-row";

    var key = document.createElement("input");
    key.type = "text";
    key.name = "claim_key";
    key.className = "theme-form-input idp-claim-input";
    key.placeholder = "claim";

    var value = document.createElement("input");
    value.type = "text";
    value.name = "claim_value";
    value.className = "theme-form-input idp-claim-input";
    value.placeholder = "value";

    var remove = document.createElement("button");
    remove.type = "button";
    remove.className = "idp-claim-remove";
    remove.title = "Remove this claim";
    remove.textContent = "×";
    remove.onclick = function () {
        container.removeChild(row);
    };

    row.appendChild(key);
    row.appendChild(value);
    row.appendChild(remove);
    container.appendChild(row);
    key.focus();
}
