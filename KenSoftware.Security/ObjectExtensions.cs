using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Reflection.Emit;

namespace Qimmah.Extensions;
public static class ObjectExtensions
{
    public static bool IsNotNullOrEmpty([NotNullWhen(true)] this object obj)
    {
        if (obj is null)
            return false;

        return obj.GetType().GetRuntimeProperties().Any(property =>
        {
            object value = property.GetValue(obj);
            return value != null;
        });
    }

    public static bool IsNotNullOrEmpty([NotNullWhen(true)] this Type obj)
    {
        if (obj is null)
            return false;

        return true;
    }

    public static bool IsNotNullOrEmpty<T>([NotNullWhen(true)] this T obj) where T : new()
    {
        if (obj is null)

            return false;

        return !obj.Equals(new T());
    }

    public static Action<S, T> CreateSetter<S, T>(FieldInfo field)
    {
        string methodName = field.ReflectedType.FullName + ".set_" + field.Name;
        DynamicMethod setterMethod = new(methodName, null, new Type[] { typeof(S), typeof(T) }, true);
        ILGenerator gen = setterMethod.GetILGenerator();

        gen.Emit(OpCodes.Ldarg_0);
        gen.Emit(OpCodes.Ldarg_1);
        gen.Emit(OpCodes.Stfld, field);
        gen.Emit(OpCodes.Ret);

        return (Action<S, T>)setterMethod.CreateDelegate(typeof(Action<S, T>));
    }
    public static object GetPropValue(this object obj, PropertyInfo Prop)
    {
        if (obj is null) return null;
        if (Prop == null) return null;
        if (Prop.DeclaringType == obj.GetType())
        {
            return Prop.GetValue(obj);
        }
        else return null;
    }
    public static object GetPropValue(this object obj, string PropName)
    {
        return obj.GetType().GetRuntimeProperty(PropName).GetValue(obj);
    }
    public static Action<S, List<T>> CreateListSetter<S, T>(FieldInfo field)
    {
        string methodName = field.ReflectedType.FullName + ".set_" + field.Name;
        DynamicMethod setterMethod = new(methodName, null, new Type[] { typeof(S), typeof(List<T>) }, true);
        ILGenerator gen = setterMethod.GetILGenerator();

        gen.Emit(OpCodes.Ldarg_0);
        gen.Emit(OpCodes.Ldarg_1);
        gen.Emit(OpCodes.Stfld, field);
        gen.Emit(OpCodes.Ret);

        return (Action<S, List<T>>)setterMethod.CreateDelegate(typeof(Action<S, List<T>>));
    }

    public static T ToAnyType<T>(this object value)
    {
        var Type = typeof(T);
        var UnderlyingType = Type.UnderlyingSystemType;

        if (value == null)
        {
            return default;
        }
        if (UnderlyingType.IsNotNullOrEmpty())
        {
            return (T)Convert.ChangeType(value, UnderlyingType);
        }
        return (T)Convert.ChangeType(value, Type);
    }
}
