# jar patch 方法



1. 在idea中新建一个projec

2. 在src 中新建一个class，名字为想要修改的class的package.controller

3. 将反编译的除了package 的内容粘到新的class中

4. 在project structure中加原始的jar和jar中的lib目录加入到library中

5. 点击build project构建出新的class

6. 如果构建出的结构目录和原始的不一致，需要在out下构建一个一致的目录，然后将刚编译出的class放到正确的位置

7. 使用命令替换掉原来jar中的class

   ```
   cd /xxx/xxx/out
   jar uvf /xxx/xxxx/xx.jar  ./BOOT-INF/XXX/XXXX/XXX.class
   ```

8. 打开压缩包反编译查看是否更新成功，或者直接运行查看是否生效

   ```
   java -jar /xxx/xxxx/xx.jar
   ```

