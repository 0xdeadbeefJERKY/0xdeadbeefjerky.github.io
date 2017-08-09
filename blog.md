---
layout: default
title: Blog
permalink: /blog/
---
<u1>
	{% for post in site.posts limit 10 %}
	<h1><a href="{{ site.baseurl }}{{ post.url }}">{{ post.title }}</a></h1>

	<h3><i><span>{{ post.date | date_to_string }}</span></i></h3>
	    {{ post.content | strip_html | truncatewords:200}}<br>
	        <a href="{{ post.url }}">Read more...</a><br><br>
	{% endfor %}
</u1>
