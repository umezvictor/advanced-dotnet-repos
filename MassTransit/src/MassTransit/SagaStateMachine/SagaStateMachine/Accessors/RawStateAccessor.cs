namespace MassTransit
{
    using System;
    using System.Linq;
    using System.Linq.Expressions;
    using System.Reflection;
    using System.Threading.Tasks;
    using Internals;


    public partial class MassTransitStateMachine<TInstance>
        where TInstance : class, SagaStateMachineInstance
    {
        class RawStateAccessor :
            IStateAccessor<TInstance>
        {
            readonly StateMachine<TInstance> _machine;
            readonly IStateObserver<TInstance> _observer;
            readonly PropertyInfo _propertyInfo;
            readonly IReadProperty<TInstance, State> _read;
            readonly IWriteProperty<TInstance, State> _write;

            public RawStateAccessor(StateMachine<TInstance> machine, Expression<Func<TInstance, State>> currentStateExpression,
                IStateObserver<TInstance> observer)
            {
                _machine = machine;
                _observer = observer;

                _propertyInfo = currentStateExpression.GetPropertyInfo();

                _read = ReadPropertyCache<TInstance>.GetProperty<State>(_propertyInfo);
                _write = WritePropertyCache<TInstance>.GetProperty<State>(_propertyInfo);
            }

            Task<State<TInstance>> IStateAccessor<TInstance>.Get(BehaviorContext<TInstance> context)
            {
                var state = _read.Get(context.Saga);
                if (state == null)
                    return Task.FromResult<State<TInstance>>(null);

                return Task.FromResult(_machine.GetState(state.Name));
            }

            Task IStateAccessor<TInstance>.Set(BehaviorContext<TInstance> context, State<TInstance> state)
            {
                if (state == null)
                    throw new ArgumentNullException(nameof(state));

                var previous = _read.Get(context.Saga);
                if (state.Equals(previous))
                    return Task.CompletedTask;

                _write.Set(context.Saga, state);

                State<TInstance> previousState = null;
                if (previous != null)
                    previousState = _machine.GetState(previous.Name);

                return _observer.StateChanged(context, state, previousState);
            }

            public Expression<Func<TInstance, bool>> GetStateExpression(params State[] states)
            {
                if (states == null || states.Length == 0)
                    throw new ArgumentOutOfRangeException(nameof(states), "One or more states must be specified");

                var parameterExpression = Expression.Parameter(typeof(TInstance), "instance");

                var statePropertyExpression = Expression.Property(parameterExpression, _propertyInfo.GetMethod);

                var stateExpression = states.Select(state => Expression.Equal(statePropertyExpression,
                    Expression.Constant(state, typeof(State)))).Aggregate((left, right) => Expression.Or(left, right));

                return Expression.Lambda<Func<TInstance, bool>>(stateExpression, parameterExpression);
            }

            public void Probe(ProbeContext context)
            {
                context.Add("currentStateProperty", _propertyInfo.Name);
            }
        }
    }
}
