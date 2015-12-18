$(function() {
    function check() {
        if(!document.getElementById("tester")) {
            if(typeof disableButtonTimer == "function") {
                disableButtonTimer();
            }
            $("input[type=submit]")
            .add("button")
                .prop("disabled", true)
                .text("Please disable AdBlock and reload")
                .val("Please disable AdBlock and reload");
        }
    }

    check();
    setInterval(check, 1000);
});
