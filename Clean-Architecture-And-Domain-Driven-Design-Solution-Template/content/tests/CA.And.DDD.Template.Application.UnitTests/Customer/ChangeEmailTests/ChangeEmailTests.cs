using CA.And.DDD.Template.Application.Customer.ChangeEmail;
using CA.And.DDD.Template.Application.Exceptions;
using CA.And.DDD.Template.Domain.Customers;
using MassTransit;
using Microsoft.Extensions.Logging;
using Moq;

namespace CA.And.DDD.Template.Application.UnitTests.Customer.ChangeEmailTests
{
    public class ChangeEmailCommandHandlerTests
    {
        private readonly Mock<ICustomerRepository> _customerRepositoryMock;
        private readonly Mock<ILogger<ChangeEmailCommandHandler>> _loggerMock;
        private readonly ChangeEmailCommandHandler _handler;

        public ChangeEmailCommandHandlerTests()
        {
            _customerRepositoryMock = new Mock<ICustomerRepository>();
            _loggerMock = new Mock<ILogger<ChangeEmailCommandHandler>>();
            _handler = new ChangeEmailCommandHandler(_customerRepositoryMock.Object, _loggerMock.Object);
        }

        [Fact]
        public async Task Should_Change_Email_When_Customer_Exists()
        {
            // Arrange
            var newEmail = "new@email.com";

            var customer = Domain.Customers.Customer.CreateCustomer(
                new CustomerId(Guid.NewGuid()),
                new FullName("Mikolaj"),
                new Age(DateTime.Now.AddYears(-30)),
                new Email("email@email.com"),
                new Address("Fifth Avenue", "10A", "1", "PL", "10037"));



            _customerRepositoryMock.Setup(repo => repo.GetAsync(customer.CustomerId.Value, default))
                                   .ReturnsAsync(customer);

            var command = new ChangeEmailCommand(customer.CustomerId.Value, newEmail);
            var consumeContextMock = Mock.Of<ConsumeContext<ChangeEmailCommand>>(c => c.Message == command);

            // Act
            await _handler.Consume(consumeContextMock);

            // Assert
            Assert.Equal(newEmail, customer.Email.Value);
            _customerRepositoryMock.Verify(repo => repo.GetAsync(It.IsAny<Guid>(), default), Times.Exactly(1));
        }

        [Fact]
        public async Task Should_Throw_CustomerNotFoundApplicationException_When_Customer_Does_Not_Exist()
        {
            // Arrange
            var customerId = Guid.NewGuid();
            var newEmail = "new@example.com";

            _customerRepositoryMock.Setup(repo => repo.GetAsync(customerId, default)).ReturnsAsync((CA.And.DDD.Template.Domain.Customers.Customer?)null);

            var command = new ChangeEmailCommand(customerId, newEmail);
            var consumeContextMock = Mock.Of<ConsumeContext<ChangeEmailCommand>>(c => c.Message == command);

            // Act & Assert
            var exception = await Assert.ThrowsAsync<CustomerNotFoundApplicationException>(() => _handler.Consume(consumeContextMock));
            _customerRepositoryMock.Verify(repo => repo.GetAsync(It.IsAny<Guid>(), default), Times.Exactly(1));

        }
    }
}
