namespace UserService.Services
{
    public interface IEventPublisher
    {
        Task PublishAsync<T>(T eventMessage);
    }

    public class EventPublisher : IEventPublisher
    {
        public Task PublishAsync<T>(T eventMessage)
        {
            Console.WriteLine($"Event Published: {eventMessage}");
            return Task.CompletedTask;
        }
    }
}
