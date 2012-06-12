package com.hush.hee.axbridge;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.antlr.stringtemplate.StringTemplate;
import org.antlr.stringtemplate.StringTemplateGroup;
import org.antlr.stringtemplate.language.AngleBracketTemplateLexer;

public class WrapperGenerator
{
	private StringTemplateGroup templates = new StringTemplateGroup(
			"templates", "code_templates", AngleBracketTemplateLexer.class);

	public static void main(String[] argv) throws IOException
	{
		new WrapperGenerator().generate();
	}

	public void generate() throws IOException
	{
		Method[] toWrap = HushEncryptionEngineInterface.class.getMethods();
		String[] methodStrings = new String[toWrap.length];
		int n = 0;
		for (Method m : toWrap)
		{
			methodStrings[n++] = methodTemplate(m);
		}
		StringTemplate classTemplate = templates.getInstanceOf("axbridgeClass");
		classTemplate.setAttribute("methods", methodStrings);
		FileUtils.writeStringToFile(new File(
				"com/hush/hee/axbridge/HushEncryptionEngineAxbridge.java"),
				classTemplate.toString());
	}

	private String methodTemplate(Method m)
	{
		Annotation[][] argAnnotations = m.getParameterAnnotations();
		String[] argumentNames = new String[argAnnotations.length];
		List<String> notNull = new LinkedList<String>();
		int x = 0;
		for (Annotation[] a : argAnnotations)
		{
			argumentNames[x] = ((HushEncryptionEngineInterface.ArgumentName) a[0])
					.name();
			if (!m.getParameterTypes()[x].isPrimitive()
					&& (a.length == 1 || !(a[1] instanceof HushEncryptionEngineInterface.CanBeNull)))
				notNull.add(argumentNames[x]);
			x++;
		}
		Class[] paramTypes = m.getParameterTypes();
		String[] paramTypeNames = new String[paramTypes.length];
		x = 0;
		for (Class t : paramTypes)
			paramTypeNames[x++] = t.getName();
		StringTemplate argumentTemplate = templates
				.getInstanceOf("axbridgeMethod");

		argumentTemplate.setAttribute("methodName", m.getName());
		argumentTemplate.setAttribute("argumentTypes", paramTypeNames);
		argumentTemplate.setAttribute("argumentNames", argumentNames);
		argumentTemplate.setAttribute("notNull", notNull);
		return argumentTemplate.toString().replaceAll("(?<!\r)\n", "\r\n");
	}

}
