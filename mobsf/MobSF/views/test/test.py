from django.shortcuts import render


def posttest(request):
    ctx ={}
    if request.POST:
        ctx['rlt'] = request.POST['q']
    return render(request, "test/post.html", ctx)


