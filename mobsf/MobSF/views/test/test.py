
import json
import logging
import os
import platform
import re
import shutil
from pathlib import Path
from wsgiref.util import FileWrapper

from django.conf import settings
from django.core.paginator import Paginator
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template.defaulttags import register


def posttest(request):
    logger.warning('weiry:posttest:posttest')
    ctx ={}
    if request.POST:
        ctx['rlt'] = request.POST['q']
    return render(request, "test/post.html", ctx)


