$(function(){
	DELETE_COUNT = 0;
	$("#submit-btn").click(function(){
		var url = $('#url-txtbox').val();
		var plist = url.split('list=')[1];
		if (plist){
			var ampersandPosition = plist.indexOf('&');
			if(ampersandPosition != -1) {
	  			plist = plist.substring(0, ampersandPosition);
			}
		}
		if (!plist ){
			var vid = url.split('v=')[1];
			var pos = vid.indexOf('&');
			if(pos != -1) {
  			vid = vid.substring(0, pos);
			}	
			download(0, [{'id': vid, 'title' : vid}]);
			return;
		}

		var startindex = $('#start-index').val();
		console.log()
		var list = plist; //'PL55713C70BA91BD6E';
		var api = 'https://gdata.youtube.com/feeds/api/playlists/' + list + '?v=2&alt=jsonc&start-index=' + startindex + '&max-results=50';
		$.ajax({
			type : 'GET',
			url : api,
			success : function(res){
				console.log(res);
				videos = {}
				for (var i=0; i< res.data.items.length; i++){
					videos[i] = {'title' : res.data.items[i]['video']['title'], 'id' : res.data.items[i]['video']['id'] };
				}
				download(0, videos)
				
			},
			error : function(args){
				console.log(args);
			}
		})
	});
	$('#refresh-btn').click(function(){
		get_files();
	});
	$('#recently-btn').click(function(){
		list_played('last_played');
	});
	$('#most-btn').click(function(){
		list_played('nplayed');
	});


	$('#videoplayer').bind("click", function(e){
		if (this.paused){
			this.play();
		} else {
			this.pause();
		}
		//$('#videoplayer').get(0).pause();
	});

	$('#existing_files').delegate('a', 'click', function(event){
		console.log(this);
		event.stopPropagation();
		$('a.selected').removeClass('selected');
		$(this).addClass('selected');
		play();
		return false;
	});
	$('body').bind("keydown", function(e){
		var code = e.keyCode || e.which;
		console.log(code);
		if (code == 110 || code == 78) play_next(false);   //n
		else if (code == 68)$('#delete-btn').click();
		else if (code == 32) { $('#videoplayer').click(); return false; } 
		else if (code == 83) {$('#shuffle').click()} //s
		else if (code == 38) volume(0.1);   //up arrow
		else if (code == 40) volume(-0.1);  // down arrow
		else if (code == 37) seek(-5);      // left arrow
		else if (code == 39) seek(5);
		else return;		//right arrow
		e.preventDefault();

	});
	$('#refresh-btn').click();
	$('#delete-btn').click(function(e){
		var fname = $("a.selected").attr('id');
		delete_file(fname);
	});
});
function delete_file(fname){
	$.ajax({
		type : 'POST',
		url : '/delete_file',
		data : {'fname': fname},
		success : function(response){
			var $old = $('a.selected').parent();
			play_next();
			$old.remove();

		}
	})

}
function get_files(){
	$.ajax({
		type : 'GET',
		url : '/list_files',
		contentType : "application/json",
		success: function(response){
			$('#existing_files').html('');
			response = JSON.parse(response);
			console.log(response);
			for (var i=0; i< response.length; i++){
				var files = response[i];
				var html = "<div><a alt=\"" + files[0] + "\""  +  "id=\"" + files[2] + "\" href='about:blank' index='" + i  + "'>" + files[2] + "</a></div>";
				$('#existing_files').append(html);
			}
			//$('#existing_files a').get(0).click();
		}
	});
}
function list_played(key){
	$.ajax({
		type : 'GET',
		url : '/list_played',
		data : {'key' : key },
		contentType : "application/json",
		success: function(response){
			$('#existing_files').html('');
			response = JSON.parse(response);
			console.log(response);
			for (var i=0; i< response.length; i++){
				var files = response[i];
				var html = "<div><a alt=\"" + files[key] + "\""  +  "id=\"" + files['name'] + "\" href='about:blank' index='" + i  + "'>" + files['name'] + "</a></div>";
				$('#existing_files').append(html);
			}
			$('#existing_files a').get(0).click();


		}
	});
}


function download(index, videos) {
	if (index >= videos.length) {
		$('#response').html($('#response').html() + ' <br /> Done' + index);
		return;
	}

	$('#response').html(index + ' Downloading ' + videos[index]['title']);
	$.ajax({
		type : 'GET',
		url :  '/play',
		data : videos[index],
		success : function(response){
			//alert(response);
			download(index+1, videos)
		}
	});
}
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}
function play_next(isended){
	var index = parseInt($("a.selected").attr('index'));
	if (isended === false){

	}
	$('a.selected').removeClass('selected');
	if ($('#shuffle').is(':checked')){
		var rand = getRandomInt(0, $('#existing_files a').length - 1);	
	} else{
		var rand = index + 1;
	}
	$('#existing_files a').get(rand).click();

}
function play(){
	var fname = $("a.selected").attr('id');
	$('#videoplayer').attr('src', '/video/' + fname);
	$('#current').html(fname);
	$('#videoplayer').attr('autoplay', true);
	$('#videoplayer').attr('controls', true);
	$('#videoplayer').get(0).play();
	$('#videoplayer').unbind('ended');
	$('#videoplayer').bind('ended', function(){
		play_next(true);
	});
	$.ajax({
		type : 'GET',
		url :  '/update_play',
		data : {'fname': fname}
	});
}

function volume(diff){
	var vol = $('#videoplayer').get(0).volume;
	if ( vol >= 0  && vol <= 1) $('#videoplayer').get(0).volume += diff;
	console.log('Volume', $('#videoplayer').get(0).volume);
}

function seek(diff){
	var video = $('#videoplayer').get(0);
	var ctime = video.currentTime;
	video.currentTime += diff;
}