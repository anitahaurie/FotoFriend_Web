function search() {
    var list = [];

    var text = $("#search-input").val();
    $("#tags .none").each(function () {
        list.push($.trim($(this).find('span').remove().end().text()));
    });

    if (text)
        list.push(text.toLowerCase());

    if (!list)
        list.push("default");

    var param = {
        keyword: list.filter(function (item, pos) {
            return list.indexOf(item) == pos;
        }) };

    $.ajax({
        url: '/search',
        traditional: true,
        type: "GET",
        data: param,
        dataType: "json",
        success: function (response) {
            var $newHtml = $(response);
            $("#place_for_tags").html($newHtml.find("#tagHTML").html());
            $("#place_for_photos").html($newHtml.find("#photos").html());
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