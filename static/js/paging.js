var theTable = document.getElementById("table2");
var totalPage = document.getElementById("spanTotalPage");
var pageNum = document.getElementById("spanPageNum");

var spanPre = document.getElementById("spanPre");
var spanNext = document.getElementById("spanNext");
var spanFirst = document.getElementById("spanFirst");
var spanLast = document.getElementById("spanLast");

var numberRowsInTable = theTable.rows.length;
var pageSize = 11;
var page = 1;

function next() {
    hideTable();
    currentRow = pageSize * page;
    maxRow = currentRow + pageSize;
    if (maxRow > numberRowsInTable) maxRow = numberRowsInTable;
    for (var i = currentRow; i < maxRow; i++) {

        theTable.rows[i].style.display = '';
    }
    page++;

    if (maxRow == numberRowsInTable) {
        nextText();
        lastText();
    }
    showPage();
    preLink();
    firstLink();
}

function pre() {
    hideTable();
    page--;
    currentRow = pageSize * page;
    maxRow = currentRow - pageSize;
    if (currentRow > numberRowsInTable) currentRow = numberRowsInTable;
    for (var i = maxRow; i < currentRow; i++) {
        theTable.rows[i].style.display = '';
    }

    if (maxRow == 0) {
        preText();
        firstText();
    }
    showPage();
    nextLink();
    lastLink();
}

function first() {
    hideTable();
    page = 1;
    for (var i = 0; i < pageSize; i++) {
        theTable.rows[i].style.display = '';
    }
    showPage();
    preText();
    nextLink();
    lastLink();
}

function last() {
    hideTable();
    page = pageCount();
    currentRow = pageSize * (page - 1);
    for (var i = currentRow; i < numberRowsInTable; i++) {
        theTable.rows[i].style.display = '';
    }
    showPage();
    preLink();
    nextText();
    firstLink();
}

function hideTable() {
    for (var i = 0; i < numberRowsInTable; i++) {
        theTable.rows[0].style.display = '';
        theTable.rows[i].style.display = 'none';
    }
}

function showPage() {
    pageNum.innerHTML = page;
}

function pageCount() {
    var count = 0;
    if (numberRowsInTable % pageSize != 0) count = 1;
    return parseInt(numberRowsInTable / pageSize) + count;
}

function preLink() {
    spanPre.innerHTML = "<a href='javascript:pre();'>Prev<<</a>";
}

function preText() {
    spanPre.innerHTML = "Prev<<";
}

function nextLink() {
    spanNext.innerHTML = "<a href='javascript:next();'>Next>></a>";
}

function nextText() {
    spanNext.innerHTML = "Next>>";
}


function firstLink() {
    spanFirst.innerHTML = "<a href='javascript:first();'>First</a>";
}

function firstText() {
    spanFirst.innerHTML = "First";
}

function lastLink() {
    spanLast.innerHTML = "<a href='javascript:last();'>Last</a>";
}

function lastText() {
    spanLast.innerHTML = "Last";
}

function hide() {
    for (var i = pageSize; i < numberRowsInTable; i++) {
        theTable.rows[i].style.display = 'none';
    }

    totalPage.innerHTML = pageCount();
    pageNum.innerHTML = '1';

    nextLink();
    lastLink();
}
hide();