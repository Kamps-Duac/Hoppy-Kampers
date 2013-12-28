import os
import re
import sys
import logging
import urllib2
from xml.dom import minidom

from string import letters

import webapp2
import jinja2

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class BaseHandler(webapp2.RequestHandler):
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
def gmaps_img(points):
    markers = '&'.join("markers=%s,%s" % (p.lat, p.lon) for p in points)
    return GMAPS_URL + markers

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
    #ip = '12.215.42.19'
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        #parse the xml and find the coordinates
        dom = minidom.parseString(content)
        coords = dom.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon, lat = coords[0].childNodes[0].nodeValue.split(',')
            return db.GeoPt(lat, lon)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

def top_arts(update = False):
    key = 'top'
    arts = memcache.get(key)
    if arts is None or update:
        logging.error("DB QUERY") #usually we would use logging.debug
        arts = db.GqlQuery("SELECT * FROM Art "
                           "ORDER BY created DESC LIMIT 10")
        arts = list(arts)
        memcache.set(key, arts)
    return arts

class MainPage(BaseHandler):
    def render_ascii(self, title="", art="", error=""):
        arts = top_arts()

        points = filter(None, (a.coords for a in arts))

        img_url = None
        if points:
            img_url = gmaps_img(points)

        self.render("ascii-page.html", title=title, art=art, 
                    error=error, arts=arts, img_url = img_url)

    def get(self):
        #self.write(self.request.remote_addr) #debug
        #self.write(repr(get_coords(self.request.remote_addr))) #debug
        return self.render_ascii()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")

        if title and art:
            a = Art(title = title, art = art)
            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords = coords
            #if we have coordinates, add them to the Art

            a.put()
            top_arts(True)

            self.redirect("/ascii") #redirect to ascii page to avoid that pesky resubmitt form
        else:
            error = "we need both a title and some artwork please!"
            self.render_ascii(error = error, title=title, art=art)

app = webapp2.WSGIApplication([('/ascii', MainPage)], debug=True)
