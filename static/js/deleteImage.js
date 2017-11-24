function deleteImage(e) {
    var url = { url: e.parentNode.children[0].src };

    $.ajax({
        url: '/delete',
        traditional: true,
        type: "GET",
        data: url,
        dataType: "json",
        success: function (response) {
            location.reload();
        },
        error: function (response) {
            console.error(response);
        }
    });
}