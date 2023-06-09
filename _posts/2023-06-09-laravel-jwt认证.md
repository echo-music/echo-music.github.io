---
layout: post
title: 如何在laravel框架中使用jwt
categories: laravel
description: 如何在laravel框架中使用jwt
keywords: laravel,jwt
---





# 一、什么是jwt?
```
JWT（JSON Web Token）是一种用于身份验证的开放标准（RFC 7519），它定义了一种紧凑且自包含的方式，用于在各方之间安全地传输信息。JWT通常用于身份验证和授权，它可以在客户端和服务器之间安全地传输用户声明信息，以便于身份验证和授权。

JWT由三部分组成：头部（Header）、载荷（Payload）和签名（Signature）。头部通常包含加密算法和令牌类型等信息，载荷包含用户声明信息，例如用户ID、角色、权限等信息，签名用于验证令牌的完整性和真实性。

JWT的工作流程通常如下：

1. 用户使用用户名和密码进行身份验证。
2. 服务器验证用户的凭据，并生成一个JWT。
3. 服务器将JWT作为响应发送给客户端。
4. 客户端将JWT保存在本地，并在每个请求中将其发送到服务器。
5. 服务器使用签名验证JWT的完整性和真实性，并解析出用户声明信息。
6. 服务器根据用户声明信息进行身份验证和授权。

JWT的优点包括：

1. 无状态：JWT在服务端不需要存储会话信息，因此可以轻松地扩展到多台服务器。
2. 自包含：JWT包含了所有必要的信息，因此可以减少服务器的请求次数。
3. 可扩展：JWT可以包含任意数量的声明信息，例如用户ID、角色、权限等信息。

需要注意的是，JWT虽然能够提供身份验证和授权功能，但它并不是万能的解决方案，仍然需要在实现时考虑安全性问题，例如使用合适的加密算法、设置合适的过期时间等。
```

好了下面开始学习在 laravel 框架中使用jwt

# 二、快速上手到跑路

## 0、环境要求：
```
laravel8+

PHP7.3+

```

## 1、安装jwt包
认证，获取token，刷线token等功能，tymon/jwt-auth 这个包，人家都给你封装好了，直接装上去用就行了。

```
composer require tymon/jwt-auth
```

## 2、在 config/app.php 文件 providers数组中 添加服务提供商，
主要是用来jwt配置文件
```
 'providers' =>[
     ...
     Tymon\JWTAuth\Providers\LaravelServiceProvider::class,
 ];
```

## 3、生成配置文件 jwt.php
生成jwt的配置文件
```
php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
```

## 4、生成jwt签名密钥,生成的密钥会放在.env配置文件中
生成token的时候需要用到该密钥
```
php artisan jwt:secret
```

This will update your `.env` file with something like `JWT_SECRET=foobar`

## 5、更新用户模型（user.php）app/models
有认证那肯定的有用户账号啦，用来创建用户账号
首先，您需要在User模型上实现Tymon\JWTAuth\Contracts\JWTSubject契约，这需要实现getJWTIdentifier（）和getJWTCustomClaims（）这两个方法。

```
<?php

namespace App\Models;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Tymon\JWTAuth\Contracts\JWTSubject;


class User extends Authenticatable implements JWTSubject
{
    use  HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var array<int, string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array<int, string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * The attributes that should be cast.
     *
     * @var array<string, string>
     */
    protected $casts = [
        'email_verified_at' => 'datetime',
    ];

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
```

## 6、配置你的身份守护

在config/auth.php文件中，您需要进行一些更改，以配置Laravel使用jwt保护来为应用程序身份验证

```
'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

...

'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],
```

在这里，我们告诉api卫士使用jwt驱动程序，并将api卫士设置为默认值。

我们现在可以使用Laravel的内置Auth系统，由jwt-Auth在幕后完成工作

## 7、添加基本的身份路由

首先，让我们在routes/api.php中添加一些路由，如下所示：

```
Route::prefix('auth')->group(function () {
    Route::post('login', [AuthController::class, 'login']);
    Route::post('logout', [AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::post('me', [AuthController::class, 'me']);

});
```

## 8、创建认证控制器 AuthController

你可以手动或运行artisan命令创建AuthController：

```
php artisan make:controller AuthController
```

您现在应该能够POST到登录端点（例如。http://example.dev/auth/login)使用一些有效凭据，然后看到如下响应：

[![pCEYMi6.png](https://s1.ax1x.com/2023/06/09/pCEYMi6.png)](https://imgse.com/i/pCEYMi6)

不好意思让你失望了,jwt库下面没有users表,别说表了，库也没有呀，那接下来我们开始新建库和表

[![pCEYGsH.png](https://s1.ax1x.com/2023/06/09/pCEYGsH.png)](https://imgse.com/i/pCEYGsH)
生成用户账号表

```
php artisan migrate
```
[![pCEYteA.png](https://s1.ax1x.com/2023/06/09/pCEYteA.png)](https://imgse.com/i/pCEYteA)

然后进入tinker

```
php artisan tinker
```

执行以下命令生成测试数据

```
>>> namespace App\Models;
> User::create(['name' => 'Test','email' =>'php_fangting@126.com','password' => bcrypt('123456')]);
```

[![pCEYDSS.png](https://s1.ax1x.com/2023/06/09/pCEYDSS.png)](https://imgse.com/i/pCEYDSS)

然后使用账号登陆获取令牌

[![pCEY2oq.png](https://s1.ax1x.com/2023/06/09/pCEY2oq.png)](https://imgse.com/i/pCEY2oq)

刷新token

[![pCEYhWT.png](https://s1.ax1x.com/2023/06/09/pCEYhWT.png)](https://imgse.com/i/pCEYhWT)

报错了，因为我们是api接口，返回这种html对前端不太友好！应该返回json

所以我们需要更新一下 `app/Exceptions/Handler.php` 中的 `render`

```
/**
     * @param $request
     * @param Throwable $e
     * @return \Illuminate\Contracts\Foundation\Application|\Illuminate\Contracts\Routing\ResponseFactory|\Illuminate\Http\JsonResponse|\Illuminate\Http\Response|\Symfony\Component\HttpFoundation\Response
     * @throws Throwable
     *
     */
    public function render($request, Throwable $e)
    {
        // 参数验证错误的异常，我们需要返回 400 的 http code 和一句错误信息
        if ($e instanceof ValidationException) {
            return response(['error' => array_first(array_collapse($e->errors()))], 400);
        }
        // 用户认证的异常，我们需要返回 401 的 http code 和错误信息
        if ($e instanceof UnauthorizedHttpException) {
            return response(['msg' => $e->getMessage(), 'code' => 401], 401);
        }

        if ($e instanceof TokenBlacklistedException) {
            return response(['msg' => $e->getMessage(), 'code' => 401], 401);
        }


        return parent::render($request, $e);
    }
```

我们再一次请求刷新token

[![pCEYIlF.png](https://s1.ax1x.com/2023/06/09/pCEYIlF.png)](https://imgse.com/i/pCEYIlF)

The token has been blacklisted" 说明这个token已经不可用了。我们需要重新登陆

## 9、用户登陆中间件开发

```
php artisan make:middleware AuthJwtToken
```

中间件代码如下：

```
<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Http\Middleware\BaseMiddleware;

class AuthJwtToken extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param \Illuminate\Http\Request $request
     * @param \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse) $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {

        // 检查此次请求中是否带有 token，如果没有则抛出异常。
        $this->checkForToken($request);

        // 使用 try 包裹，以捕捉 token 过期所抛出的 TokenExpiredException  异常
        try {
            // 检测用户的登录状态，如果正常则通过
            if ($this->auth->parseToken()->authenticate()) {
                return $next($request);
            }
            throw new UnauthorizedHttpException('jwt-auth', '未登录');
        } catch (TokenExpiredException $exception) {
            // 此处捕获到了 token 过期所抛出的 TokenExpiredException 异常，我们在这里需要做的是刷新该用户的 token 并将它添加到响应头中
            try {
                // 刷新用户的 token
                $token = $this->auth->refresh();
                // 使用一次性登录以保证此次请求的成功
                auth('api')->onceUsingId($this->auth->manager()->getPayloadFactory()->buildClaimsCollection()->toPlainArray()['sub']);
            } catch (JWTException $exception) {
                // 如果捕获到此异常，即代表 refresh 也过期了，用户无法刷新令牌，需要重新登录。
                throw new UnauthorizedHttpException('jwt-auth', $exception->getMessage());
            }
        }

        // 在响应头中返回新的 token
        return $this->setAuthenticationHeader($next($request), $token);

    }
}
```

## 其他

postman使用技巧

每次请求都要携带token,所以我们在一个地方设置全局token并保存后面，每次请求都会自动携带

[![pCEYTOJ.png](https://s1.ax1x.com/2023/06/09/pCEYTOJ.png)](https://imgse.com/i/pCEYTOJ)

参考资料

https://jwt-auth.readthedocs.io/en/develop/laravel-installation/

[Laravel5.5使用jwt完成token认证 - 车车大人 - 博客园](https://www.cnblogs.com/ccdr/p/11721503.html)