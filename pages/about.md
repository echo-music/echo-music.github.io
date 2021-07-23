---
layout: page
title: About
description: 程序人生
keywords: Yuewu Liu, baxibaba, able, baxi
comments: true
menu: 关于
permalink: /about/
---

我是baxibaba，目前在研究、分享开源技术。

坚信熟能生巧，技术改变人生。

业余羽毛球、快走、游泳爱好者。

## 联系

{% for website in site.data.social %}
* {{ website.sitename }}：[@{{ website.name }}]({{ website.url }})
{% endfor %}

## Skill Keywords

{% for category in site.data.skills %}
### {{ category.name }}
<div class="btn-inline">
{% for keyword in category.keywords %}
<button class="btn btn-outline" type="button">{{ keyword }}</button>
{% endfor %}
</div>
{% endfor %}
