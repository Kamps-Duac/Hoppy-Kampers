import os
import re
import random
import hashlib
import hmac
import logging
import json
from string import letters
from datetime import datetime, timedelta

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

SECRET = 'canttelu'

def render_str(templete, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
       self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        #check to see if the user is logged in or not
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.username = uid and User.by_id(int(uid))

        if self.request.url.endswith('json'):
            self.format = 'json'
        else:
            self.format = 'html'

class Home(BaseHandler):
    def get(self):
        self.render('home.html')

#### user
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))

def age_get(key):
    r = memcache.get(key)
    if r:
        val, save_time = r
        age = (datetime.utcnow() - save_time).total_seconds()
    else:
        val, age = None, 0

    return val, age

def add_post(post):
    post.put()
    get_posts(update = True)
    return str(post.key().id())

def get_posts(update = False):
    q = Blog.all().order('-created').fetch(limit = 10)
    mc_key = 'BLOGS'

    blogs, age = age_get(mc_key)
    if update or blogs is None:
        blogs = list(q)
        age_set(mc_key, blogs)

    return blogs, age

def age_str(age):
    s = 'queried %s seconds ago'
    age = int(age)
    if age == 1:
        s = s.replace('seconds', 'second')
    return s % age

class User(db.Model):
    # User object stored in the database
    user_name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod # Decorator. Says you can call this method on this object
    def by_id(cls, uid): #cls is referring to this class User, not an instance of the User
        return User.get_by_id(uid, parent = users_key()) #get_by_id is keyword for data store

    @classmethod
    def by_name(cls, user_name):
        u = User.all().filter('user_name =', user_name).get()
        return u

    @classmethod
    def register(cls, user_name, pw, email = None):
        pw_hash = make_pw_hash(user_name, pw)
        return User(parent = users_key(),
                    user_name = user_name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, user_name, pw):
        u = cls.by_name(user_name)
        if u and valid_pw(user_name, pw, u.pw_hash):
            return u

#### /user
#### blog

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Blog(db.Model):
    #base info
    name = db.StringProperty(required = True)
    style = db.StringProperty(required = False)
    recipe_type = db.StringProperty(required = False)
    size = db.Property(required = False)
    og = db.Property(required = False)
    fg = db.Property(required = False)
    description = db.TextProperty(required = False)
    #Ingredients
    malt = db.StringProperty(required = False)
    hops = db.StringProperty(required = False)
    yeast = db.StringProperty(required = False)
    #old stuff
    content = db.TextProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("blog-newpost.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'name' : self.name,
             'style' : self.style,
             'recipe_type' : self.recipe_type,
             'size' : self.size,
             'og' : self.og,
             'fg' : self.fg,
             'description' : self.description,
             'malt' : self.malt,
             'hops' : self.hops,
             'yeast' : self.yeast,
             'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt),
             }

        return d

class BlogFront(BaseHandler):
    def get(self):
        posts, age = get_posts()

        if self.format == 'html':
            self.render('blog-front.html', blogs = posts, age = age_str(age))
        else:
            return self.render_json([p.as_dict() for p in blogs])

    # def post(self):
    #     name = self.request.get("name")
    #     content = self.request.get("content")

    #     if name and content:
    #         a = Blog(name = name, content = content)
    #         a.put()

    #         self.redirect("/blog") #redirect to blog page to avoid that pesky resubmitt form
    #     else:
    #         error = "we need both a name and some contents please!"
    #         self.render_blog(error = error, name = name, content=content)

class NewPost(BaseHandler):
    def render_blog(self, name="", content="", error=""):
        blogs = db.GqlQuery("SELECT * FROM Blog "
                            "ORDER BY created DESC")
        self.render("blog-newpost.html", name = name, content = content, error = error, blogs = blogs)

    def get(self):
        self.render_blog()

    def post(self):
        name = self.request.get("name")
        content = self.request.get("content")
        style = self.request.get("style")
        recipe_type = self.request.get("recipe_type")
        size = self.request.get("size")
        og = self.request.get("og")
        fg = self.request.get("fg")
        description = self.request.get("description")
        malt = self.request.get("malt")
        hops = self.request.get("hops")
        yeast = self.request.get("yeast")

        error = {}

        if not name and not content: #for now, less required fields
            error['name_error'] = "What is the beer called?"
            self.render_blog(error = error, name = name, 
                             content = content, style = style,
                             recipe_type = recipe_type, size = size,
                             og = og, fg = fg, description = description,
                             malt = malt, hops = hops, yeast = yeast)
        else:
            a = Blog(parent = blog_key(), name = name, content = content,
                     style = style, recipe_type = recipe_type, size = size,
                     og = og, fg = fg, description = description,
                     malt = malt, hops = hops, yeast = yeast)
            a_key = add_post(a)
            memcache.flush_all()
            self.redirect("/blog/%s" % a_key) #we want to redirect to permalink for blog
            



USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Permalink(BaseHandler):
    def get(self, blog_id):
        #post_key = blog_id
        #blog_id = 'BLOGS' #debug
        #post_key = 'BLOGS' #debug

        post, age = age_get(blog_id)
        if not post:
            key = db.Key.from_path('Blog', int(blog_id), parent=blog_key())
            post = db.get(key)
            age_set(blog_id, post)
            age = 0

        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("blog-perma.html", blog = post, age = age_str(age))
        else:
            self.render_json(post.as_dict())

class Signup(BaseHandler):
    def get(self):
        self.render('signup.html')


    def post(self):
        error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username, email = self.email)
                      #'user_error' = "", 'password_error'='', 'verify_error'='',
                      #'email_error'='')

        if not valid_username(self.username):
            params['user_error'] = "Invalid Username!"
            error = True
        if not valid_password(self.password):
            params['password_error'] = 'Invalid password!'
            error = True
        if self.password != self.verify:
            params['verify_error'] = "Passwords don't match!"
            error = True
        if not valid_email(self.email):
            params['email_error'] = "That's not a valid email."
            error = True

        if error:
            self.render('signup.html', **params)
        else:
            self.done()
            # self.response.headers['Content-Type'] = 'text/plain'
            # self.response.headers.add_header('Set-Cookie', 'username=%s' % make_secure_val(str(self.username)))
            # self.redirect("/welcome")

        def done(self, *a, **kw):
            # done does nothing in this class, but other classes can overwrite it
            raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', user_error = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Welcome(BaseHandler):
    def get(self):
        #username = self.request.cookies.get('user_id')
        if self.username:
            self.render("welcome.html", username = self.username.user_name)
        else:
            self.redirect("/signup")

class Login(BaseHandler):
    def get(self):
        self.render('login.html')


    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)
            
class Logout(BlogFront):
    def get(self):
        self.logout()
        self.redirect('/signup')

class Flush(BaseHandler):
    def get(self):
        memcache.flush_all()
        self.redirect('/blog')




app = webapp2.WSGIApplication([('/', Home),
                               ('/blog/signup', Register),
                               ('/welcome', Welcome),
                               ('/blog/?(?:.json)?', BlogFront), 
                               ('/blog/newpost', NewPost),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/blog/([0-9]+)(?:.json)?', Permalink),
                               ('/blog/flush', Flush)], debug=True)
