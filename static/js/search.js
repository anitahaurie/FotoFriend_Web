function search() {
    var list = [];

    var text = $("#search-input").val();
    $("#tags .none").each(function () {
        list.push($.trim($(this).find('span').remove().end().text()));
    });

    list.push(text);

    var param = { keyword: list };

    $.ajax({
        url: '/search',
        traditional: true,
        type: "GET",
        data: param,
        dataType: "json",
        success: function (response) {
            $("#place_for_tags").html(response);
        },
        error: function (response) {
            console.error(response);
        }
    });

    $("#search-input").val("");
}

function remove(e) {
    e.parentNode.parentNode.removeChild(e.parentNode);
}

$("#search").click(search);
$("#search-input").keyup(function (e) {
    if (e.keyCode == 13)
        search();
});