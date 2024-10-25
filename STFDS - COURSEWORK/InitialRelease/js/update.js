var kmc_xmlhttp;

var activities = {};
var append_activities = 0;

// This is where the incoming responses are identifed and handled.
function kmc_process_type(type, aa)
{
    if (type == 'redirect') // redirect to another page
    {
      var where = aa['where'];
      where = where.replace(/\%26/g,'&');
      window.location.href = where;

    } else if (type == 'message') // display a message on the current page
    {
      var code = aa['code'];
      var text  = aa['text'];
      var where_html = document.getElementById('message');

      if (where_html != null)
      {
        where_html.innerHTML = text + ' ('+code+')';
      }

    } else if (type == 'vcount') // display a message on the current page
    {
      var vtype = aa['vtype'];
      var count  = aa['count'];
      var where_html = document.getElementById('sum_'+vtype);

      if (where_html != null)
      {
        where_html.innerHTML = count;
      }

    } else if (type == 'location') // insert class date/time/etc details into a page, replacing existing details when required.
    {
      var locid = aa['id'];
      var name  = decodeURI(aa['name']);

      kmc_add_to_location_list(locid, name);

    } else if (type == 'total') // update the total.
    {
      var total = aa['total'];
      var where_html = document.getElementById('total');

      if (where_html != null)
      {
        where_html.innerHTML = total;
      }
    } 
}


// a print print function for a date
function kmc_show_date(when)
{
    var d = new Date(when * 1000)

    return d.toDateString()
}

// a print print function for date and time.
function kmc_show_time(when)
{
    var d = new Date(when * 1000)

    return d.toGMTString()
}


function kmc_radio_value(radio)
{
  var rs = document.getElementsByName(radio);

  for (var i = 0, length = rs.length; i < length; i++)
  {
    if (rs[i].checked)
    {
      return rs[i].value;
    }
  }
  return '-1';
}

function kmc_response()
{
  var res;
  var aa;

  if (kmc_xmlhttp.readyState == 4)
  {
    res = kmc_xmlhttp.responseText;

    aa = JSON.parse(res)

    for(var i = 0, len = aa.length; i < len; i += 1)
    {
      var type = aa[i]['type'];
  
      kmc_process_type(type, aa[i]);
    }
  }
}

function kmc_send_post(where,what)
{
    kmc_xmlhttp = new XMLHttpRequest()
    kmc_xmlhttp.onreadystatechange=kmc_response;
    kmc_xmlhttp.open('POST',where,true);
    kmc_xmlhttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    kmc_xmlhttp.send(what);
}

function kmc_add_to_location_list(id,name)
{
  var opt = document.createElement('option');
    opt.value = id;
    opt.innerHTML = name;
    select = document.getElementById('ofLocation');
    select.appendChild(opt);
}

encodeURIComponent

// action commands

function command_login()
{

    username = encodeURIComponent(document.getElementById('ofUser').value);
    password = encodeURIComponent(document.getElementById('ofPassword').value);

    kmc_send_post('/action?command=login','{"command":"login","username":"'+username+'","password":"'+password+'"}');
}

function command_logout()
{
    kmc_send_post('/action?command=logout','{"command":"logout"}');
}


function command_location()
{
    kmc_send_post('/action?command=location','{"command":"location"}');
}

function command_summary()
{
  road = encodeURIComponent(document.getElementById('ofLocation').value);
  kmc_send_post('/action?command=summary', '{"command":"summary", "location":' + road +'}');
}

function command_add()
{
  road = encodeURIComponent(document.getElementById('ofLocation').value);
  type = encodeURIComponent(kmc_radio_value('ofType'));
  occupancy = encodeURIComponent(kmc_radio_value('ofOccupancy'));
  kmc_send_post('/action?command=add', '{"command":"add", "location":' + road + ',"type":' + type + ',"occupancy":' + occupancy + '}');
}

function command_undo()
{
  road = encodeURIComponent(document.getElementById('ofLocation').value);
  type = encodeURIComponent(kmc_radio_value('ofType'));
  occupancy = encodeURIComponent(kmc_radio_value('ofOccupancy'));
  kmc_send_post('/action?command=undo', '{"command":"undo", "location":' + road + ',"type":' + type + ',"occupancy":' + occupancy + '}');
}

