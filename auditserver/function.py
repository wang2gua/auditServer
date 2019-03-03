from django.http import HttpResponse
from django.shortcuts import render

from django.views.decorators.csrf import csrf_exempt


from . import test,audit,process

import json

def home(request):
    return render(request,'home.html')
@csrf_exempt
def count(request):
    print(request)
    print(request.POST['text'])
    user_text = request.POST['text']
    lines = user_text.split('\n')
    processor = process.Process()
    processor.process_notation(lines)
    auditor = audit.Audition()
    res = auditor.audit(lines)
    return HttpResponse(json.dumps(res))

def demo(request):
    data = [{'a':1,'b':2}]
    js = json.dumps(data)
    return HttpResponse(js)
